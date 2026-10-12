# IBM i SAVF checksum fixer and object editor

`savf_checksum_demo.py` is a standalone Python tool for IBM i save files
(SAVFs). It provides four commands:

- `fix` recalculates the per-record and global checksums;
- `list` prints the saved objects;
- `add` copies an object from a donor SAVF; and
- `remove` deletes an object.

Every command that creates a SAVF writes a new file and leaves its input files
unchanged. The `add` and `remove` commands repair every dependent record and
global checksum in the output automatically.

## Requirements

- Python 3.9 or later; no third-party Python packages are required
- `sandbox.ser` extracted from the public jSAVF 1.83 distribution

The checksum commands extract the 2,048-byte lookup table from byte offset 27
of `sandbox.ser` and verify this SHA-256 before using it:

```text
93f81fd81523a2521cf17b234edb05155998bc7e46d88b966b4bd9eef64c0764
```

Download jSAVF and extract the resource:

```sh
curl -fL -A 'Mozilla/5.0' -O https://www.anerty.net/dl/jsavf-dist-1.83-jars-only-linux.tar.xz
tar -xf jsavf-dist-1.83-jars-only-linux.tar.xz
unzip -p jsavf/jSAVF-1.83.jar net/anerty/os400/savf/check/sandbox.ser > sandbox.ser
```

By default, commands that calculate checksums read `sandbox.ser` from the
current directory. Pass `--table-resource PATH` after the command arguments to
use another location.

## Usage

```text
python3 savf_checksum_demo.py [-h]
    {fix,list,add,remove} ...
```

## Fix checksums

Recalculate every physical-record trailer, the global checksum, and the final
record trailer, then validate the generated output:

```sh
python3 savf_checksum_demo.py fix input.FILE fixed.FILE
```

This command repairs SAVF container checksums. It does not alter saved-object
data to undo an intentional modification.

## List objects

Validate the physical record trailers and list the object names in the QSYS
catalogue:

```sh
python3 savf_checksum_demo.py list input.FILE
```

This is the only command that does not require `sandbox.ser`.

## Add an object

Copy one complete object descriptor, its referenced catalogue metadata, and all
of its linked uncompressed items from a donor SAVF into a target SAVF:

```sh
python3 savf_checksum_demo.py add \
    target.FILE donor.FILE output.FILE OBJECT
```

The target and donor must be checksum-valid SAVFs using compatible,
uncompressed QSYS catalogue layouts. Create them for the same IBM i release
and source-library context. The object name must occur exactly once in the
donor and must not already exist in the target.

The target catalogue must have an unused descriptor slot and enough unused
space for the donor metadata. The command copies the complete object
descriptor, referenced catalogue metadata, and linked items; relocates copied
catalogue references; assigns unique item ordinals; and repairs the complete
SAVF checksum state.

The command writes a new SAVF and leaves both inputs unchanged.

## Remove an object

Remove one complete object descriptor and all linked items:

```sh
python3 savf_checksum_demo.py remove \
    input.FILE output.FILE OBJECT
```

The input must contain at least two saved objects, and the selected name must
identify exactly one catalogue descriptor. The command removes that
descriptor and all linked items, compacts the retained descriptors and items,
updates their links, and repairs the complete SAVF checksum state.

## Supported layout

The object editor deliberately supports only the uncompressed QSYS item and
catalogue layout validated by the accompanying research. It is not a general
parser for every historical SAVF variant. It rejects compressed items,
incompatible catalogue layouts, ambiguous object names, unknown item links,
insufficient catalogue space, and unsupported catalogue conditions instead of
guessing.

Keep an untouched copy of every input and use disposable SAVFs when testing
edited output on IBM i.

## Validation

The final script was tested locally and on IBM i 7.5 with uncompressed SAVFs
containing a `*PGM` and a `*SRVPGM`:

- adding either object to a compatible single-object SAVF produced a valid
  two-object SAVF;
- removing either object from tool-generated and native two-object SAVFs
  produced a valid one-object SAVF;
- `CPYFRMSTMF` accepted every checksum-fixed, added-object, and removed-object
  result;
- `DSPSAVF` listed the expected objects; and
- `RSTOBJ` restored every listed object in the tested outputs.

Separate controls with a stale global checksum and with a damaged record
trailer were rejected by `CPYFRMSTMF`. In both cases, `fix` reproduced the
original valid SAVF byte for byte; the repaired files were then accepted,
listed, and restored successfully.

These results validate the tool for the tested layout and IBM i environment;
they are not a claim of support for compressed or otherwise incompatible SAVF
formats.
