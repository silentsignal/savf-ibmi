"""List, edit, and repair IBM i SAVFs using reconstructed checksums.

Python 3.9 or later is required. The lookup table is loaded from sandbox.ser,
which readers can extract from their own jSAVF 1.83 distribution.
"""

import argparse
import hashlib
from dataclasses import dataclass
from pathlib import Path
from typing import Sequence


PHYSICAL_RECORD_SIZE = 528
PAYLOAD_SIZE = 512
TRAILER_SIZE = 16
GLOBAL_FIELD_SIZE = 16
GLOBAL_BACKUP_OFFSET = 0x40
MASK64 = (1 << 64) - 1
CATALOGUE_POINTER_FIELDS = (0x48, 0x4c)
CATALOGUE_BLOCK_ALIGNMENT = 0x20
ITEM_ORDINAL_OFFSET = 0xd0

EXPECTED_TABLE_SHA256 = (
    "93f81fd81523a2521cf17b234edb05155998bc7e46d88b966b4bd9eef64c0764"
)


@dataclass(frozen=True)
class SavfItem:
    offset: int
    length: int
    name: str
    item_type: int
    srds_offset: int
    total_length: int
    metadata_length: int
    header_occupation: int


@dataclass(frozen=True)
class QsysObject:
    descriptor_offset: int
    name: str
    descriptor: bytes


@dataclass(frozen=True)
class QsysCatalogue:
    items: tuple[SavfItem, ...]
    srds: SavfItem
    logical_offset: int
    data: bytes
    descriptor_offset: int
    descriptor_length: int
    objects: tuple[QsysObject, ...]


@dataclass(frozen=True)
class EditResult:
    data: bytes
    object_name: str
    objects: tuple[str, ...]
    old_record_count: int
    new_record_count: int


def load_table(path: str = "sandbox.ser") -> bytes:
    resource = Path(path).read_bytes()
    if len(resource) < 27 + 2048:
        raise ValueError("sandbox.ser is too short")
    table = resource[27:27 + 2048]
    digest = hashlib.sha256(table).hexdigest()
    if digest != EXPECTED_TABLE_SHA256:
        raise ValueError(f"unexpected lookup-table SHA-256: {digest}")
    return table


def chk_add(source: bytearray, destination: bytearray) -> None:
    shift_carry = 0
    add_carry = 0

    for index in range(len(source) - 1, -1, -1):
        value = source[index]
        shifted = ((value << 1) | shift_carry) & 0xff
        shift_carry = value >> 7

        total = shifted + destination[index + 1] + add_carry
        add_carry = total >> 8
        destination[index + 1] = total & 0xff

    destination[0] = (
        destination[0] + add_carry + shift_carry
    ) & 0xff


def reduce_once(data: bytes, input_sizes: Sequence[int]) -> bytes:
    parts = []
    offset = 0
    for size in input_sizes:
        parts.append(bytearray(data[offset:offset + size]))
        offset += size
    if offset != len(data):
        raise ValueError("reduction sizes do not cover the input")

    accumulators = parts[0:6] + [parts[7], parts[6]]
    for index in range(7):
        chk_add(accumulators[index], accumulators[index + 1])
    return bytes(accumulators[7])


def compute_record_checksum(
    sequence: int, payload: bytes, timestamp: bytes
) -> bytes:
    if len(payload) != PAYLOAD_SIZE:
        raise ValueError("record payload must be 512 bytes")
    if len(timestamp) != 8:
        raise ValueError("timestamp must be 8 bytes")

    phase1 = reduce_once(
        sequence.to_bytes(4, "big") + payload,
        [61, 62, 63, 64, 65, 66, 68, 67],
    )
    phase2 = reduce_once(
        phase1,
        [5, 6, 7, 8, 9, 10, 12, 11],
    )

    result = bytearray(phase2)
    for index in range(8):
        result[index] ^= timestamp[index]
    return sequence.to_bytes(4, "big") + bytes(result)


def rotate_left_64_be(state: bytearray, count: int = 29) -> None:
    value = int.from_bytes(state, "big", signed=False)
    value = ((value << count) | (value >> (64 - count))) & MASK64
    state[:] = value.to_bytes(8, "big")


def build_spread_tables() -> tuple[list[int], list[int]]:
    spread1 = [0] * 256
    for byte in range(256):
        value = 0
        for bit in range(7, -1, -1):
            value = (value << 2) | ((byte >> bit) & 1)
        spread1[byte] = value
    spread2 = [(value << 1) & 0xffff for value in spread1]
    return spread1, spread2


def shuffle(
    state: bytearray, spread1: Sequence[int], spread2: Sequence[int]
) -> None:
    output = bytearray(8)
    for pair in range(4):
        value = spread2[state[pair]] | spread1[state[pair + 4]]
        output[pair * 2:pair * 2 + 2] = value.to_bytes(2, "big")
    state[:] = output


def mix_half(
    half: bytes,
    state: bytearray,
    counter: int,
    threshold: int,
    table: bytes,
    spread1: Sequence[int],
    spread2: Sequence[int],
) -> tuple[int, bool]:
    window = bytes([half[7]]) + half
    for index in range(8):
        table_index = (
            (window[index] << 8) | window[index + 1]
        ) & 0x7ff
        state[index] ^= table[table_index]

    rotate_left_64_be(state, 29)

    threshold_event = counter == threshold
    if threshold_event:
        counter = 0
        shuffle(state, spread1, spread2)
    return counter, threshold_event


def _payloads(physical: bytes) -> list[bytes]:
    if not physical or len(physical) % PHYSICAL_RECORD_SIZE:
        raise ValueError("SAVF size must be a nonzero multiple of 528")
    return [
        physical[offset:offset + PAYLOAD_SIZE]
        for offset in range(0, len(physical), PHYSICAL_RECORD_SIZE)
    ]


def logical_stream(physical: bytes, restore_backup: bool = False) -> bytes:
    records = _payloads(physical)
    logical = bytearray(b"".join(records))
    if restore_backup:
        logical[-GLOBAL_FIELD_SIZE:] = logical[
            GLOBAL_BACKUP_OFFSET:GLOBAL_BACKUP_OFFSET + GLOBAL_FIELD_SIZE
        ]
    return bytes(logical)


def _u32(data: bytes, offset: int) -> int:
    return int.from_bytes(data[offset:offset + 4], "big")


def parse_uncompressed_items(logical: bytes) -> list[SavfItem]:
    if len(logical) < PAYLOAD_SIZE or len(logical) % PAYLOAD_SIZE:
        raise ValueError("logical SAVF size must be a multiple of 512")

    first_item = _u32(logical, 0x34) or PAYLOAD_SIZE
    if first_item % PAYLOAD_SIZE or first_item < PAYLOAD_SIZE:
        raise ValueError("unsupported first-item offset")

    items = []
    offset = first_item
    while offset < len(logical):
        if offset + PAYLOAD_SIZE > len(logical):
            raise ValueError("truncated SAVF item header")
        if logical[offset:offset + 4] != b"\xff" * 4:
            raise ValueError(f"missing item marker at logical 0x{offset:x}")

        name = logical[offset + 4:offset + 14].decode("cp037").rstrip()
        item_type = int.from_bytes(
            logical[offset + 0x22:offset + 0x24], "big"
        )
        srds_offset = _u32(logical, offset + 0x24) & 0x00ffffff
        header_occupation = _u32(logical, offset + 0x44)
        length = (_u32(logical, offset + 0x48) + 1) * PAYLOAD_SIZE
        metadata_length = _u32(logical, offset + 0x56)
        total_length = _u32(logical, offset + 0xcc) * PAYLOAD_SIZE
        packed_length = int.from_bytes(
            logical[offset + 0x170:offset + 0x178], "big"
        ) + PAYLOAD_SIZE

        if packed_length != PAYLOAD_SIZE or length != total_length:
            raise ValueError(
                f"item {name!r} uses an unsupported packed/compressed layout"
            )
        if not length or length % PAYLOAD_SIZE or offset + length > len(logical):
            raise ValueError(f"invalid length for item {name!r}")

        items.append(
            SavfItem(
                offset=offset,
                length=length,
                name=name,
                item_type=item_type,
                srds_offset=srds_offset,
                total_length=total_length,
                metadata_length=metadata_length,
                header_occupation=header_occupation,
            )
        )
        offset += length

    if offset != len(logical):
        raise ValueError("item chain does not cover the logical stream")
    return items


def parse_qsys_catalogue(logical: bytes) -> QsysCatalogue:
    items = parse_uncompressed_items(logical)
    srds_items = [item for item in items if item.item_type == 0x19db]
    if len(srds_items) != 1 or items[0] != srds_items[0]:
        raise ValueError("this operation supports one leading QSYS SRDS item")

    srds = srds_items[0]
    if not srds.metadata_length or srds.metadata_length > srds.total_length:
        raise ValueError("invalid SRDS metadata length")

    catalogue_offset = (
        srds.offset + srds.total_length - srds.metadata_length
    )
    catalogue = logical[
        catalogue_offset:catalogue_offset + srds.metadata_length
    ]
    if not catalogue or catalogue[0] == 0:
        raise ValueError("unsupported non-QSYS SRDS catalogue")

    target_release = catalogue[1]
    descriptor_offset = 112 if target_release >= 66 else 80
    descriptor_length = 151 if target_release > 48 else 87
    object_count = _u32(catalogue, 42)
    descriptor_end = descriptor_offset + object_count * descriptor_length
    if descriptor_end > len(catalogue):
        raise ValueError("SRDS object descriptor table is truncated")

    objects = []
    for index in range(object_count):
        offset = descriptor_offset + index * descriptor_length
        descriptor = bytes(catalogue[offset:offset + descriptor_length])
        name = descriptor[0:30].decode("cp037").rstrip()
        objects.append(QsysObject(offset, name, descriptor))

    known_offsets = {obj.descriptor_offset for obj in objects}
    unknown_links = [
        item for item in items[1:]
        if item.srds_offset and item.srds_offset not in known_offsets
    ]
    if unknown_links:
        raise ValueError("an item refers to an unknown SRDS descriptor")

    return QsysCatalogue(
        items=tuple(items),
        srds=srds,
        logical_offset=catalogue_offset,
        data=catalogue,
        descriptor_offset=descriptor_offset,
        descriptor_length=descriptor_length,
        objects=tuple(objects),
    )


def _select_object(
    objects: Sequence[QsysObject], object_name: str
) -> QsysObject:
    wanted = object_name.upper()
    matches = [obj for obj in objects if obj.name.upper() == wanted]
    if len(matches) != 1:
        raise ValueError(
            f"object name {object_name!r} matched {len(matches)} descriptors"
        )
    return matches[0]


def _catalogue_pointers(
    descriptor: bytes, catalogue_length: int
) -> tuple[int, ...]:
    pointers = []
    for offset in CATALOGUE_POINTER_FIELDS:
        value = int.from_bytes(descriptor[offset:offset + 4], "big")
        if value:
            pointers.append(value >> 8)
    result = tuple(pointers)
    if not result:
        raise ValueError("object descriptor has no catalogue metadata")
    if any(pointer >= catalogue_length for pointer in result):
        raise ValueError("object descriptor has an invalid catalogue pointer")
    return result


def _catalogue_object_block(
    layout: QsysCatalogue, selected: QsysObject
) -> tuple[int, bytes]:
    selected_pointers = _catalogue_pointers(
        selected.descriptor, len(layout.data)
    )
    selected_start = min(selected_pointers)
    starts = sorted(
        min(_catalogue_pointers(obj.descriptor, len(layout.data)))
        for obj in layout.objects
    )
    selected_end = next(
        (start for start in starts if start > selected_start),
        len(layout.data),
    )
    if any(
        pointer < selected_start or pointer >= selected_end
        for pointer in selected_pointers
    ):
        raise ValueError("object catalogue metadata overlaps another object")
    used = layout.data[selected_start:selected_end]
    nonzero = [index for index, value in enumerate(used) if value]
    if not nonzero:
        raise ValueError("object catalogue metadata is empty")
    return selected_start, used[:nonzero[-1] + 1]


def _align(value: int, alignment: int) -> int:
    return (value + alignment - 1) // alignment * alignment


def _require_valid_savf(physical: bytes, table: bytes) -> bytes:
    invalid, stored, calculated = validate_file(physical, table)
    if invalid or stored != calculated:
        raise ValueError("input is not a checksum-valid SAVF")
    return logical_stream(physical, restore_backup=True)


def _finish_edited_logical(
    logical: bytearray, old_global: bytes, table: bytes
) -> bytes:
    if len(logical) % PAYLOAD_SIZE:
        raise AssertionError("edited logical stream is not record-aligned")

    record_count = len(logical) // PAYLOAD_SIZE
    logical[0x08:0x0c] = record_count.to_bytes(4, "big")
    logical[0x38:0x40] = record_count.to_bytes(8, "big")

    tail = bytes(logical[-GLOBAL_FIELD_SIZE:])
    logical[
        GLOBAL_BACKUP_OFFSET:GLOBAL_BACKUP_OFFSET + GLOBAL_FIELD_SIZE
    ] = tail
    logical[-GLOBAL_FIELD_SIZE:] = old_global

    repaired = repair(_pack_logical_with_record_checksums(bytes(logical)), table)
    invalid, stored, calculated = validate_file(repaired, table)
    if invalid or stored != calculated:
        raise AssertionError("failed to repair edited SAVF")
    return repaired


def _pack_logical_with_record_checksums(logical: bytes) -> bytes:
    if not logical or len(logical) % PAYLOAD_SIZE:
        raise ValueError("logical SAVF size must be a nonzero multiple of 512")
    timestamp = logical[0:8]
    physical = bytearray()
    for index in range(len(logical) // PAYLOAD_SIZE):
        payload = logical[index * PAYLOAD_SIZE:(index + 1) * PAYLOAD_SIZE]
        physical.extend(payload)
        physical.extend(compute_record_checksum(index + 1, payload, timestamp))
    return bytes(physical)


def compute_global_checksum(physical: bytes, table: bytes) -> bytes:
    if len(table) != 2048:
        raise ValueError("lookup table must be 2,048 bytes")
    records = _payloads(physical)

    spread1, spread2 = build_spread_tables()
    s0 = bytearray([0x55] * 8)
    s8 = bytearray([0xaa] * 8)
    c0, c8 = 1, 121
    backup = records[0][
        GLOBAL_BACKUP_OFFSET:GLOBAL_BACKUP_OFFSET + GLOBAL_FIELD_SIZE
    ]

    for record_index, record in enumerate(records):
        payload = bytearray(record)
        if record_index == len(records) - 1:
            payload[-GLOBAL_FIELD_SIZE:] = backup

        for offset in range(0, PAYLOAD_SIZE, 16):
            block = bytes(payload[offset:offset + 16])

            c0, _ = mix_half(
                block[0:8], s0, c0, 251, table, spread1, spread2
            )
            c0 += 1

            c8, s8_event = mix_half(
                block[8:16], s8, c8, 257, table, spread1, spread2
            )
            if s8_event:
                old_s0_tail = bytes(s0[4:8])
                s0[4:8] = s8[4:8]
                s8[4:8] = old_s0_tail
            c8 += 1

    return bytes(s0) + bytes(s8)


def validate_records(physical: bytes) -> list[int]:
    _payloads(physical)
    timestamp = physical[0:8]
    invalid = []
    record_count = len(physical) // PHYSICAL_RECORD_SIZE
    for index in range(record_count):
        start = index * PHYSICAL_RECORD_SIZE
        payload = physical[start:start + PAYLOAD_SIZE]
        stored = physical[
            start + PAYLOAD_SIZE:start + PHYSICAL_RECORD_SIZE
        ]
        expected = compute_record_checksum(index + 1, payload, timestamp)
        if stored != expected:
            invalid.append(index)
    return invalid


def validate_file(physical: bytes, table: bytes) -> tuple[list[int], bytes, bytes]:
    invalid = validate_records(physical)
    stored_global = physical[-32:-16]
    calculated_global = compute_global_checksum(physical, table)
    return invalid, stored_global, calculated_global


def repair(physical: bytes, table: bytes) -> bytes:
    data = bytearray(physical)
    _payloads(data)
    timestamp = bytes(data[0:8])
    record_count = len(data) // PHYSICAL_RECORD_SIZE

    for index in range(record_count):
        start = index * PHYSICAL_RECORD_SIZE
        payload = bytes(data[start:start + PAYLOAD_SIZE])
        data[start + PAYLOAD_SIZE:start + PHYSICAL_RECORD_SIZE] = (
            compute_record_checksum(index + 1, payload, timestamp)
        )

    data[-32:-16] = compute_global_checksum(bytes(data), table)

    final_start = (record_count - 1) * PHYSICAL_RECORD_SIZE
    final_payload = bytes(data[final_start:final_start + PAYLOAD_SIZE])
    data[final_start + PAYLOAD_SIZE:final_start + PHYSICAL_RECORD_SIZE] = (
        compute_record_checksum(record_count, final_payload, timestamp)
    )
    return bytes(data)


def remove_qsys_object(
    physical: bytes, table: bytes, object_name: str
) -> EditResult:
    logical_bytes = _require_valid_savf(physical, table)
    logical = bytearray(logical_bytes)
    stored_global = physical[-32:-16]
    layout = parse_qsys_catalogue(logical_bytes)
    catalogue = bytearray(layout.data)

    if len(layout.objects) < 2:
        raise ValueError("remove requires at least two saved objects")
    target = _select_object(layout.objects, object_name)
    kept_objects = [obj for obj in layout.objects if obj != target]
    descriptor_map = {
        obj.descriptor_offset: (
            layout.descriptor_offset + index * layout.descriptor_length
        )
        for index, obj in enumerate(kept_objects)
    }
    target_items = [
        item for item in layout.items[1:]
        if item.srds_offset == target.descriptor_offset
    ]
    if not target_items:
        raise ValueError("no SAVF item is linked to the selected object")
    if any(not item.srds_offset for item in layout.items[1:]):
        raise ValueError("unsupported unlinked item after the QSYS catalogue")

    old_descriptor_end = (
        layout.descriptor_offset
        + len(layout.objects) * layout.descriptor_length
    )
    catalogue[42:46] = len(kept_objects).to_bytes(4, "big")
    for index, obj in enumerate(kept_objects):
        start = layout.descriptor_offset + index * layout.descriptor_length
        catalogue[start:start + layout.descriptor_length] = obj.descriptor
    unused_start = (
        layout.descriptor_offset
        + len(kept_objects) * layout.descriptor_length
    )
    catalogue[unused_start:old_descriptor_end] = bytes(
        old_descriptor_end - unused_start
    )
    logical[
        layout.logical_offset:layout.logical_offset + len(catalogue)
    ] = catalogue

    first_item = layout.items[0].offset
    edited = bytearray(logical[:first_item])
    retained_items = []
    for item in layout.items:
        if item in target_items:
            continue
        chunk = bytearray(logical[item.offset:item.offset + item.length])
        if item.srds_offset:
            new_offset = descriptor_map[item.srds_offset]
            link = _u32(chunk, 0x24)
            chunk[0x24:0x28] = (
                (link & 0xff000000) | new_offset
            ).to_bytes(4, "big")
            retained_items.append(bytes(chunk))
        edited.extend(chunk)

    repaired = _finish_edited_logical(edited, stored_global, table)
    repaired_logical = logical_stream(repaired, restore_backup=True)
    repaired_layout = parse_qsys_catalogue(repaired_logical)
    actual_items = repaired_layout.items[1:]
    if len(actual_items) != len(retained_items):
        raise AssertionError("retained item count changed unexpectedly")
    for item, expected in zip(actual_items, retained_items):
        actual = repaired_logical[item.offset:item.offset + item.length]
        if actual != expected:
            raise AssertionError(f"retained item {item.name!r} changed")

    return EditResult(
        data=repaired,
        object_name=target.name,
        objects=tuple(obj.name for obj in kept_objects),
        old_record_count=len(physical) // PHYSICAL_RECORD_SIZE,
        new_record_count=len(repaired) // PHYSICAL_RECORD_SIZE,
    )


def add_qsys_object(
    physical: bytes,
    donor_physical: bytes,
    table: bytes,
    object_name: str,
) -> EditResult:
    logical_bytes = _require_valid_savf(physical, table)
    donor_logical = _require_valid_savf(donor_physical, table)
    logical = bytearray(logical_bytes)
    stored_global = physical[-32:-16]

    layout = parse_qsys_catalogue(logical_bytes)
    donor_layout = parse_qsys_catalogue(donor_logical)
    catalogue = bytearray(layout.data)

    if (
        layout.data[0:34] != donor_layout.data[0:34]
        or layout.descriptor_offset != donor_layout.descriptor_offset
        or layout.descriptor_length != donor_layout.descriptor_length
    ):
        raise ValueError("target and donor catalogue layouts are incompatible")
    if any(obj.name.upper() == object_name.upper() for obj in layout.objects):
        raise ValueError(f"object {object_name!r} already exists in target")

    donor_object = _select_object(donor_layout.objects, object_name)
    source_items = [
        item for item in donor_layout.items[1:]
        if item.srds_offset == donor_object.descriptor_offset
    ]
    if not source_items:
        raise ValueError("no donor SAVF item is linked to the selected object")

    new_descriptor_offset = (
        layout.descriptor_offset
        + len(layout.objects) * layout.descriptor_length
    )
    new_descriptor_end = new_descriptor_offset + layout.descriptor_length
    if new_descriptor_end > len(catalogue):
        raise ValueError("QSYS catalogue has no room for another descriptor")
    if any(catalogue[new_descriptor_offset:new_descriptor_end]):
        raise ValueError("next QSYS catalogue descriptor slot is not empty")

    donor_metadata_offset, donor_metadata = _catalogue_object_block(
        donor_layout, donor_object
    )
    target_used_end = max(
        index for index, value in enumerate(catalogue) if value
    ) + 1
    target_metadata_offset = _align(
        max(target_used_end, new_descriptor_end),
        CATALOGUE_BLOCK_ALIGNMENT,
    )
    target_metadata_end = target_metadata_offset + len(donor_metadata)
    if target_metadata_end > len(catalogue):
        raise ValueError("QSYS catalogue has no room for object metadata")
    if any(catalogue[target_metadata_offset:target_metadata_end]):
        raise ValueError("QSYS catalogue metadata space is not empty")

    new_descriptor = bytearray(donor_object.descriptor)
    metadata_delta = target_metadata_offset - donor_metadata_offset
    for offset in CATALOGUE_POINTER_FIELDS:
        value = int.from_bytes(new_descriptor[offset:offset + 4], "big")
        if value:
            pointer = value >> 8
            pointer += metadata_delta
            if pointer >= len(catalogue):
                raise ValueError("relocated catalogue pointer is invalid")
            new_descriptor[offset:offset + 4] = (
                (pointer << 8) | (value & 0xff)
            ).to_bytes(4, "big")

    catalogue[42:46] = (len(layout.objects) + 1).to_bytes(4, "big")
    catalogue[new_descriptor_offset:new_descriptor_end] = (
        new_descriptor
    )
    catalogue[target_metadata_offset:target_metadata_end] = donor_metadata
    logical[
        layout.logical_offset:layout.logical_offset + len(catalogue)
    ] = catalogue

    edited = bytearray(logical)
    appended_items = []
    ordinal = max(
        _u32(logical, item.offset + ITEM_ORDINAL_OFFSET)
        for item in layout.items
    )
    for item in source_items:
        chunk = bytearray(
            donor_logical[item.offset:item.offset + item.length]
        )
        link = _u32(chunk, 0x24)
        chunk[0x24:0x28] = (
            (link & 0xff000000) | new_descriptor_offset
        ).to_bytes(4, "big")
        ordinal += 1
        chunk[
            ITEM_ORDINAL_OFFSET:ITEM_ORDINAL_OFFSET + 4
        ] = ordinal.to_bytes(4, "big")
        appended_items.append(bytes(chunk))
        edited.extend(chunk)

    repaired = _finish_edited_logical(edited, stored_global, table)
    repaired_logical = logical_stream(repaired, restore_backup=True)
    repaired_layout = parse_qsys_catalogue(repaired_logical)
    if (
        repaired_layout.data[
            target_metadata_offset:target_metadata_end
        ] != donor_metadata
    ):
        raise AssertionError("added catalogue metadata changed unexpectedly")
    actual_items = repaired_layout.items[len(layout.items):]
    if len(actual_items) != len(appended_items):
        raise AssertionError("added item count changed unexpectedly")
    for item, expected in zip(actual_items, appended_items):
        actual = repaired_logical[item.offset:item.offset + item.length]
        if actual != expected:
            raise AssertionError(f"added item {item.name!r} changed")

    return EditResult(
        data=repaired,
        object_name=donor_object.name,
        objects=tuple(obj.name for obj in layout.objects)
        + (donor_object.name,),
        old_record_count=len(physical) // PHYSICAL_RECORD_SIZE,
        new_record_count=len(repaired) // PHYSICAL_RECORD_SIZE,
    )


def list_qsys_objects(physical: bytes) -> list[str]:
    invalid = validate_records(physical)
    if invalid:
        numbers = ", ".join(str(index + 1) for index in invalid)
        raise ValueError(f"invalid record trailers: {numbers}")
    logical = logical_stream(physical, restore_backup=True)
    layout = parse_qsys_catalogue(logical)
    return [obj.name for obj in layout.objects]


def add_table_argument(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--table-resource",
        default="sandbox.ser",
        help="sandbox.ser extracted from jSAVF (default: sandbox.ser)",
    )


def write_new_file(path: str, data: bytes, *inputs: str) -> None:
    output = Path(path).resolve()
    if output in {Path(value).resolve() for value in inputs}:
        raise ValueError("output path must differ from every input path")
    Path(path).write_bytes(data)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)

    fix_parser = subparsers.add_parser(
        "fix",
        help="recalculate all SAVF checksum fields",
    )
    fix_parser.add_argument("input", help="input SAVF")
    fix_parser.add_argument("output", help="new checksum-repaired SAVF")
    add_table_argument(fix_parser)

    list_parser = subparsers.add_parser(
        "list",
        help="list objects in a SAVF",
    )
    list_parser.add_argument("input", help="input SAVF")

    add_parser = subparsers.add_parser(
        "add",
        help="copy an object from a donor SAVF",
    )
    add_parser.add_argument("input", help="target SAVF")
    add_parser.add_argument("donor", help="SAVF containing the object")
    add_parser.add_argument("output", help="new SAVF")
    add_parser.add_argument("object", help="object name")
    add_table_argument(add_parser)

    remove_parser = subparsers.add_parser(
        "remove",
        help="remove an object from a SAVF",
    )
    remove_parser.add_argument("input", help="input SAVF")
    remove_parser.add_argument("output", help="new SAVF")
    remove_parser.add_argument("object", help="object name")
    add_table_argument(remove_parser)
    return parser


def execute(args: argparse.Namespace) -> int:
    physical = Path(args.input).read_bytes()

    if args.command == "list":
        for name in list_qsys_objects(physical):
            print(name)
        return 0

    table = load_table(args.table_resource)

    if args.command == "fix":
        output = repair(physical, table)
        invalid, stored, calculated = validate_file(output, table)
        if invalid or stored != calculated:
            raise AssertionError("checksum repair verification failed")
        write_new_file(args.output, output, args.input)
        print(f"checksum repaired: {args.output}")
        return 0

    if args.command == "add":
        donor = Path(args.donor).read_bytes()
        result = add_qsys_object(
            physical, donor, table, args.object
        )
        write_new_file(args.output, result.data, args.input, args.donor)
        print(f"added object: {result.object_name}")
        print(f"objects: {', '.join(result.objects)}")
        print(
            f"record count: {result.old_record_count} -> "
            f"{result.new_record_count}"
        )
        return 0

    if args.command == "remove":
        result = remove_qsys_object(
            physical, table, args.object
        )
        write_new_file(args.output, result.data, args.input)
        print(f"removed object: {result.object_name}")
        print(f"objects: {', '.join(result.objects)}")
        print(
            f"record count: {result.old_record_count} -> "
            f"{result.new_record_count}"
        )
        return 0

    raise AssertionError("unreachable")


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()
    try:
        return execute(args)
    except (OSError, UnicodeError, ValueError) as error:
        parser.error(str(error))
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
