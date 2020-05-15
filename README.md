# IRATI Wireshark dissector

This Git repository contains a dissector for Wireshark which can dissect packets exchanged by the [IRATI stack](https://github.com/IRATI/stack/), an implementation of RINA.
The dissector can parse EFCP and CDAP PDUs.
Currently only the outermost DIF is parsed.

## Installing the dissector

To use this dissector with Wireshark, install the `efcp.lua` file in the Wireshark plugin directory (or create a symlink).
The location of the Wireshark plugin directory for your operating system can be found in the [documentation of Wireshark](https://www.wireshark.org/docs/wsug_html_chunked/ChPluginFolders.html).

### Dissecting CDAP PDUs (optional)

To optionally dissect the CDAP messages, follow the next steps:

1. Fetch [`rina-tools/src/rlite/CDAP.proto`](https://github.com/IRATI/stack/blob/master/rina-tools/src/rlite/CDAP.proto) from the [IRATI stack Git repository](https://github.com/IRATI/stack) and put `CDAP.proto` a directory of your choice (for instance alongside `efcp.lua` in the Wireshark plugin directory).

2. Configure the search path for the the Protobuf Wireshark plugin to include the directory where you put `CDAP.proto`.
Wireshark's documentation on this topic can be found [here](https://www.wireshark.org/docs/wsug_html_chunked/ChProtobufSearchPaths.html).

**Note:** for now, it is necessary to edit `CDAP.proto` as Wireshark chokes on `[default = 0]` in the file so remove that part.

## Configuring the dissector

As the length of the various fields can differ per DIF, the dissector has several preferences to change these which can be configured in Wireshark (Edit -> Preferences -> Protocols -> EFCP).

## Authors

- Caspar Schutijser, SIDN Labs
- Joeri de Ruiter, SIDN Labs

## License

This project is distributed under the MIT license, see [LICENSE](LICENSE).

