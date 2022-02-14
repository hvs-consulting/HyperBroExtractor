# HyperBroExtractor
This script is able to decrypt Stage 2, decompress Stage 2, extract Stage 3, and parse the configuration of the HyperBro malware commonly used by APT 27, also known under the following names: Emissary Panda, LuckyMouse, Bronze Union, Group-3390, and Iron Tiger. 

Note that the decryption key or compression algorithm can be changed anytime by APT27. Furthermore, the addresses used to parse the configuration from Stage 3 are hardcoded, which might easily break in a newer version of the malware. If the configuration parser fails, you can still use the "-d" option to dump all strings after the decryption. We also tried to make the script easily adaptable for future changes of the malware.

For more information and technical details please refer to out public report: https://www.hvs-consulting.de/en/threat-intelligence-report-emissary-panda-apt27

# Installation and Execution
For the decompression of Stage 3 we use a [Python implementation for LZNT1](https://github.com/you0708/lznt1). The requirements can be installed with the following command:

```
$ pip3 install -r requirements.txt
```

All other options of the script can be found in the help output of the script:
```
$ python3 HyperBro_extract_config.py -h
```