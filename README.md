# MysteryGiftTool Fork
![License](https://img.shields.io/badge/License-GPLv3-blue.svg)

Automatic tracking/downloading/decryption/extraction of Gen VI/VII Mystery Gifts/PGL Regulations. Modified by evandixon of Project Pokémon for portability.

Requirements:
- .Net Core 2.0
- 3DS ARM9 BootROM
- Client Certificate and Password

MysteryGiftTool makes use of [PKHeX-Core](https://github.com/kwsch/PKHeX). This requires using the following MyGet feed:
```
https://www.myget.org/F/projectpokemon/api/v3/index.json
```

Usage:
```
MysteryGiftTool <Boot9 Path> <ClCertA Path> <ClCertA Password>
```

![Example of extracted mystery gifts](/img/example.PNG)
