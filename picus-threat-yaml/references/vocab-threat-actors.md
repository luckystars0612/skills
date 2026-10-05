# Threat actors — complete list with aliases

> Pulled from `GET /v1/threat-library/action-parameters` / `GET /v1/threat-library/threat-actors` on the live platform, 2026-10-05.
> Picus **validates these on import** — a value outside the list is rejected. The endpoint
> accepts a `module_name` query parameter but ignores it: the response is byte-identical for
> all 12 modules, so one list serves every module.

Used in the campaign-level `threat_actor` field. Must match the **`name`** column exactly;
the alias column is there so you can map an intel report's naming to Picus's.

**206 actors.**

| `threat_actor` | Also known as |
|---|---|
| `8220 Gang` | 8220 Mining Group, Returned Libra, Water Sigbin |
| `APT-C-36` | Blind Eagle |
| `APT-C-44` | — |
| `APT18` | TG-0416, Dynamite Panda, Threat Group-0416, Wekby, Scandium |
| `APT19` | Codoso, C0d0so0, Codoso Team, Sunshop Group |
| `APT20` | APT8, Violin Panda, TH3Bug, Crawling Taurus |
| `APT28` | IRON TWILIGHT, SNAKEMACKEREL, Swallowtail, Group 74, Sednit, Sofacy, Pawn Storm, Fancy Bear, STRONTIUM, Tsar Team, Threat Group-4127, TG-4127, Forest Blizzard, FROZENLAKE, GruesomeLarch, SIG40, ATK 5, T-APT-12, ITG05, TAG-0700, UAC-0028, Grey-Cloud, Grizzly Steppe, BlueDelta, TA422, Fighting Ursa, Blue Athena, UAC-0063, TAG-110, Sofacy Group, UAC-0001, Zebrocy |
| `APT29` | APT-C-42, ATK 7, Blue Dev 5, Blue Kitsune, BlueBravo, Cloaked Ursa, CloudLook, Cozy Bear, Cozy Duke, CozyDuke, Cranefly, Dark Halo, Dukes, Earth Koshchei, Grizzly Steppe, Group 100, IRON HEMLOCK, IRON RITUAL, ITG11, Midnight Blizzard, Minidionis, NobelBaron, NOBELIUM, NobleBaron, SilverFish, Solar Phoenix, SolarStorm, StellarParticle, TEMP.Monkey, TEMP.Monkeys, The Dukes, UNC2452, UNC3524, YTTRIUM, UNC6293 |
| `APT3` | Bronze Mayfair, Buckeye,Gothic Panda, Group 6, Pirpi,Red Sylvan, TG-0110, Threat Group-0110, UPS, UPS Team |
| `APT32` | SeaLotus, OceanLotus, APT-C-00, Canvas Cyclone, BISMUTH, Ocean Buffalo, Tin Woodlawn, ATK 17, SectorF01, Pond Loach, APT-LY-100, Lotus Bane |
| `APT33` | Elfin, Magnallium, Holmium, ATK 35, Refined Kitten, TA451, Cobalt Trinity, Peach Sandstorm, Yellow Orc, Curious Serpens |
| `APT37` | InkySquid, ScarCruft, Reaper, Group123, TEMP.Reaper, Ricochet Chollima, Cerium, Red Eyes, Geumseong121, Venus 121, Hermit, ATK 4, ITG10, Ruby Sleet, Crooked Pisces, Moldy Pisces, Osmium, Opal Sleet, TA-RedAnt, Inky Squid, Venus121 |
| `APT38` | NICKEL GLADSTONE, BeagleBoyz, Bluenoroff, Stardust Chollima, Sapphire Sleet, COPERNICIUM, Alluring Pisces, CageyChameleon, CryptoCore, CryptoMimic, Dangerous Password, HIDDEN COBRA, Lazarus Group, Leery Turtle, TA444, TAG-71 |
| `APT39` | Chafer, Remix Kitten, Cobalt Hickman, TA454, ITG07, Radio Serpens |
| `APT41` | BARIUM, Blackfly, Brass Typhoon, Bronze Atlas, Bronze Export, Choiceguard, Cycldek, Dalbit, Earth Baku, Earth Lusca, Gallium, GREF, Group72, Higaisa, M00nlight, Moray, Othorene, Pigfish, Red Dev 10, RedAlpha, Reddev4, RedGolf, Redkelpi, Sparklinggoblin, TA415, Tick, Wicked Panda, Winnti, Winnti Group |
| `APT42` | GreenBravo |
| `Agrius` | DEV-0227, BlackShadow, AMERICIUM, Pink Sandstorm, Agonizing Serpens, Spectral Kitten |
| `Andariel` | Onyx Sleet,Plutonium,Silent Chollima,Stonefly |
| `Antlion` | — |
| `Aoqin Dragon` | UNC94 |
| `BITTER` | T-APT-17, TA397 |
| `BRONZE BUTLER` | REDBALDKNIGHT, Tick, CTG-2006, TEMP.Tick, Stalker Panda, Stalker Taurus |
| `Bitwise Spider` | LockBit, LockBitSupp, Fox William Mulder |
| `BlackTech` | Circuit Panda, Radio Panda, Palmerworm, TEMP.Overboard, T-APT-03, Red Djinn, Manga Taurus, Earth Hundun |
| `Blackwood` | — |
| `Boss Spider` | Gold Lowell, CTG-0007 |
| `Bounty Jackal` | 05716nnm, Nnm05716, NoName, NoName057, NoName057(16) |
| `Brain Spider` | 5BIRD, 5MRBID, 8BASE, AcidLow, bigboss, bigrichy, Birdy, BOSS, brain, Dispossessor, EightBase, exp3rt, FASTPRISONER, Lions, RADAR, RAID, RedTeam, REDTEAMDR, reverse5net, SawGoD, Signature |
| `Buhtrap` | Ratopak Spider, UAC-0008 |
| `CURIUM` | Imperial Kitten, Tortoiseshell, TA456, Marcella Flores, Houseblend, Crimson Sandstorm, Yellow Liderc, APT35, Cuboid Sandstorm, DEV-0056, DEV-0228, Smoke Sandstorm |
| `Cadet Blizzard` | DEV-0586 |
| `Calypso` | Bronze Medley |
| `Cascade Panda` | LuoYu, Storm-0601 |
| `Chimera` | Chimera |
| `ChinaZ` | — |
| `Cleaver` | Threat Group 2889, TG-2889 |
| `Cobalt Group` | GOLD KINGSWOOD, Cobalt Gang, Cobalt Spider, ATK 67, TAG-CR3, Mule Libra, Country |
| `Cold River` | Nahr el bared, Nahr Elbard, Cobalt Edgewater, TA446, Seaborgium, TAG-53, BlueCharlie, Blue Callisto, Calisto, Star Blizzard, UNC4057, Gossamer Bear, COLDRIVER, Callisto, DancingSalome, UAC-0036 |
| `Confucius` | Confucius APT |
| `Contagious Interview` | Contagious Interview, Famous Chollima, Nickel Tapestry, Storm-1877, UNC5267, Wagemole, Gwisin Gang, Itworkers, Storm0287, Tenacious Pungsan, Void Dokkaebi |
| `CopyKittens` | Slayer Kitten |
| `Cotton Sandstorm` | Emennet Pasargad, HAYWIRE KITTEN, Holy Souls, MARNANBRIDGE, NEPTUNIUM |
| `Curly Spider` | Storm-1811 |
| `CyberAv3ngers` | Soldiers of Soloman |
| `DEV-0139` | Citrine Sleet |
| `DEV-0530` | — |
| `DEV-1084` | Storm-1084 |
| `Daggerfly` | Evasive Panda, BRONZE HIGHLAND |
| `Dark Caracal` | — |
| `DarkCasino` | Water Hydra |
| `DarkHydrus` | ATK 77,Obscure Serpens,LazyMeerkat |
| `Darkhotel` | DUBNIUM, Zigzag Hail, APT-C-06, SIG25, Fallout Team, Shadow Crane, CTG-1948, Tungsten Bridge, ATK 52, Higaisa, T-APT-02, Luder |
| `DeathStalker` | Deceptikons |
| `Donot Team` | APT-C-35, SectorE02 |
| `Doppel Spider` | Gold Heron, Grief Group |
| `DragonOK` | Bronze Overbrook, Shallow Taurus |
| `Dragonfly` | ATK 6,Berserk Bear,Bromine,Crouching Yeti,DYMALLOY,Dragonfly 2.0,Energetic Bear,Ghost Blizzard,Group 24,IRON LIBERTY,ITG15,Koala Team,TEMP.Isotope,TG-4192 |
| `EXOTIC LILY` | — |
| `Earth Krahang` | — |
| `Earth Lusca` | Aquatic Panda, BountyGlad, Bronze University, Charcoal Typhoon, CHROMIUM, ControlX, Red Dev 10, Red Scully, Red Scylla, TAG-22 |
| `Ember Bear` | UNC2589, Bleeding Bear, DEV-0586, Cadet Blizzard, Frozenvista, UAC-0056 |
| `Equation` | Equation Group, Tilded Team, Platinum Colony, APT-C-40 |
| `Evilnum` | Jointworm, TA4563 |
| `FIN13` | Elephant Beetle |
| `FIN4` | Wolf Spider |
| `FIN6` | ATK 88, Camouflage Tempest, FIN8, Gold Franklin, ITG08, Magecart Group 6, Skeleton Spider, Storm-0538, TAAL, TAG-CR2, White Giant |
| `FIN7` | GOLD NIAGARA, ITG14, Carbon Spider, ELBRUS, Sangria Tempest, Calcium, Navigator, ATK 32, APT-C-11, TAG-CR1 |
| `FIN8` | ATK 113, Syssphinx |
| `Ferocious Kitten` | — |
| `Fox Kitten` | UNC757, Parisite, Pioneer Kitten, RUBIDIUM, Lemon Sandstorm, Cobalt Foxglove, UNC757 |
| `Frozen Spider` | Medusa |
| `GALLIUM` | Granite Typhoon, Phantom Panda, Alloy Taurus |
| `GOLD SOUTHFIELD` | Pinchy Spider, Gold Garden |
| `Gallmaker` | — |
| `Gamaredon Group` | IRON TILDEN, Primitive Bear, ACTINIUM, Armageddon, Shuckworm, DEV-0157, Aqua Blizzard, Winterflounder, BlueAlpha, Blue Otso, SectorC08, Callisto, Trident Ursa, UAC-0010 |
| `Gelsemium` | — |
| `Ghost` | Cring, Crypt3r, Phantom, Strike, Hello, Wickrme, HsHarada, Rapture |
| `Goblin Panda` | 1937CN,Conimes,Cycldek |
| `GoldenJackal` | — |
| `Goldmouse` | APT-C-27,ATK 80,Golden Rat |
| `Gorgon Group` | Subaat, ATK 92, TAG-CR5, Pasty Draco |
| `GreenCharlie` | — |
| `HAFNIUM` | Operation Exchange Marauder, Silk Typhoon, Red Dev 13 |
| `HEXANE` | Lyceum, Siamesekitten, Spirlin, ATK 120, Yellow Dev 9, Cobalt Lyceum |
| `Hades` | — |
| `Harvester` | - |
| `HomeLand Justice` | Karma, Void Manticore, Storm-842 |
| `Hook Spider` | BenjaminFranklin, Big-Bro, Pirat-Networks, crasty_bro, pirat, pirat-network |
| `Inception` | Inception Framework, Cloud Atlas |
| `Indra` | — |
| `Indrik Spider` | Evil Corp, Manatee Tempest, DEV-0243, UNC2165, Gold Drake, Gold Winter, Manatee Tempest, Blue Lelantos |
| `Infy` | APT-C-07,Operation Mermaid,Prince of Persia |
| `InvisiMole` | UAC-0035 |
| `KNOTWEED` | Denim Tsunami,DSIR |
| `Karakurt` | — |
| `Ke3chang` | APT15, Mirage, Vixen Panda, GREF, Playful Dragon, RoyalAPT, NICKEL, Nylon Typhoon, Bronze Palace, Bronze Davenport, Bronze Idlewood, CTG-9246, BackdoorDiplomacy, Playful Taurus, Flea, Red Vulture |
| `Kimsuky` | Black Banshee, Velvet Chollima, Emerald Sleet, THALLIUM, APT43, TA427, Springtail, SharpTongue, ITG16, TA406, ARCHIPELAGO, KTA082, UAT-5394, Sparkling Pisces, Larva-24005 |
| `LAPSUS$` | DEV-0537, Strawberry Tempest |
| `LUNAR SPIDER` | Gold SwathMore, Wizard Spider, Gold Blackburn, BokBot, IcedID |
| `Lazarus Group` | Labyrinth Chollima, HIDDEN COBRA, Guardians of Peace, ZINC, NICKEL ACADEMY, Diamond Sleet, Group 77, Hastati Group, Whois Hacking Team, NewRomanic Cyber Army Team, Appleworm, APT-C-26, ATK 3, SectorA01, ITG03, TA404, DEV-0139, Gods Apostles, Gods Disciples, UNC577, UNC2970, UNC4034, UNC4736, UNC4899, Citrine Sleet, Jade Sleet, TraderTraitor, Gleaming Pisces, Slow Pisces, BeagleBoyz, Black Artemis, Moonstone Sleet, Selective Pisces, TEMP.Hermit |
| `LazyScripter` | — |
| `Leafminer` | Raspite, Flash Kitten |
| `Leviathan` | MUDCARP, Kryptonite Panda, Gadolinium, BRONZE MOHAWK, TEMP.Jumper, APT40, TEMP.Periscope, Gingham Typhoon |
| `Lightning Spider` | Apolog, Satacom |
| `LookBack` | TA410, Witchetty, LookingFrog, FlowingFrog |
| `Lotus Blossom` | DRAGONFISH, Spring Dragon, RADIUM, Raspberry Typhoon, Bilbug, Thrip, Billbug, Bronze Elgin, CTG-8171, ATK 1, ATK 78, Red Salamander |
| `Machete` | APT-C-43, El Machete, TEMP.Andromeda, ATK 97, TAG-NS1 |
| `Madi` | Mahdi |
| `Magic Hound` | TA453, COBALT ILLUSION, Charming Kitten, Phosphorus, Newscaster, APT35, Mint Sandstorm, Cobalt Mirage, TEMP.Beanie, Timberworm, Tarh Andishan, TunnelVision, UNC788, Yellow Garuda, Educated Manticore, Ballistic Bobcat, CharmingCypress |
| `MalKamak` | Operation GhostShell |
| `Maze Team` | Gold Village, TA2101, Twisted Spider |
| `Merchant Spider` | Br0k3r |
| `Molerats` | ATK 89,Aluminum Saratoga,Extreme Jackal,Gaza Cybergang,Gaza Hackers Team,Operation Molerats,TA402,TAG-CT5 |
| `MoneyTaker` | — |
| `Moonstone Sleet` | Storm-1789 |
| `Moses Staff` | DEV-0500, Marigold Sandstorm, Abraham's Ax, Cobalt Sapling, Vengeful Kitten, White Dev 95 |
| `MuddyWater` | Earth Vetala, MERCURY, Static Kitten, Seedworm, TEMP.Zagros, Mango Sandstorm, TA450, Cobalt Ulster, ATK 51, T-APT-14, ITG17, Boggy Serpens, Yellow Nix |
| `MurenShark` | — |
| `Mustang Panda` | Bronze President, TEMP.Hex, HoneyMyte, Red Lich, Earth Preta, Camaro Dragon, PKPLUG, Stately Taurus, Twill Typhoon, Hive0154, G0129, TA416 |
| `Mustard Tempest` | DEV-0206, TA569, GOLD PRELUDE, UNC1543, Imposter Spider, Ce2021-0408, FakeBrowserUpdates, SilverFish, SocGholish |
| `Mutant Spider` | — |
| `Naikon` | Hellsing,ITG06,Lotus Panda |
| `Nazar` | SIG37 |
| `Nitro Spider` | — |
| `Nomadic Octopus` | DustSquad |
| `OPERA1ER` | Common Raven, DESKTOP-GROUP, NXSMS, Bluebottle |
| `Odyssey Spider` | TA558 |
| `OilRig` | APT34, ATK 40, COBALT GYPSY, Chrysene, Crambus, EUROPIUM, Evasive Serpens, Hazel Sandstorm, Helix Kitten, IRN2, ITG13, OilRig, TA452, Twisted Kitten, Earth Simnavaz, DEV-0861, Scarred Manticore, Yellow Maero, Storm-0861, UNC1860 |
| `Operation Earth Kitsune` | — |
| `Operation Ghostwriter` | UNC1151, TA445, UAC-0051, UAC-0057, PUSHCHA, DEV-0257, Storm-0257 |
| `Outlaw` | — |
| `POLONIUM` | Plaid Rain |
| `PROMETHIUM` | StrongPity, APT-C-41 |
| `Pat Bear` | APT-C-37, Racquet Bear |
| `Patchwork` | Hangover Group, Dropping Elephant, Chinastrats, MONSOON, Operation Hangover, APT-C-09, Quilted Tiger, TG-4410, Zinc Emerson, ATK 11, Thirsty Gemini, Capricorn Organisation, Maha Grass |
| `PowerPool` | — |
| `Predatory Sparrow` | Gonjeshke Darande |
| `Prophet Spider` | UNC961 |
| `Punk Spider` | Akira, Storm‑1567, GOLD SAHARA, REDBIKE |
| `Putter Panda` | APT2, MSUpdater, TG-6952, Group 36, Sulphur, SearchFire |
| `RA Group` | RA |
| `Rampant Kitten` | — |
| `Recess Spider` | PLAY, PlayCrypt |
| `Red Menshen` | — |
| `RedCurl` | Red Wolf, Earth Kapre |
| `Rocke` | Iron Group, Aged Libra |
| `Rocket Kitten` | Newscaster, NewsBeef, Group 83, Parastoo |
| `RomCom` | DEV-0978, Void Rabisu, Storm-0978, Tropical Scorpius, UNC2596 |
| `Salt Typhoon` | GhostEmperor,UNC2286,FamousSparrow,Earth Estries |
| `Sandworm Team` | Iron Viking, CTG-7263, Voodoo Bear, Quedagh, TEMP.Noble, ATK 14, BE2, UAC-0082, UAC-0113, UAC-0125, UAC-0133, FROZENBARENTS, IRIDIUM, Seashell Blizzard, APT44, Blue Echidna, ELECTRUM, Telebots, BlackEnergy (Group) |
| `Scarab` | UAC-0026 |
| `Scattered Spider` | Roasted 0ktapus, Octo Tempest, Storm-0875, DEV-0671, DEV-0971, Dev0875, LUCR-3, Muddled Libra, Scatter Swine, Scatteredspider, UNC3944 |
| `Scion Spider` | — |
| `Sea Turtle` | Teal Kurma, Marbled Dust, Cosmic Wolf, SILICON |
| `SharpPanda` | Sharp Dragon |
| `ShinyHunters` | - |
| `ShroudedSnooper` | — |
| `SideCopy` | — |
| `Sidewinder` | T-APT-04, Rattlesnake, Razor Tiger, APT-C-17, Hardcore Nationalist, HN2, APT-Q-39, BabyElephant, GroupA21 |
| `Silence` | Whisper Spider, Contract Crew, TEMP.TruthTeller, ATK 86, TAG-CR8 |
| `Silver Fox` | Void Arachne |
| `Slingshot` | — |
| `Star Blizzard` | SEABORGIUM, Callisto Group, TA446, COLDRIVER |
| `Sticky Werewolf` | — |
| `Storm-2603 ` | — |
| `Suckfly` | — |
| `Sweed` | — |
| `TA505` | ATK 103, CHIMBORAZO, CL0p, Cl0p, Clop, FIN11, Gold Evergreen, Gold Tahoe, Graceful Spider, Hive0065, Lace Tempest, Odinaff, Ragnarlocker, SectorJ04, Spandex Tempest, TEMP.Warlock |
| `TA551` | GOLD CABIN, Shathak, Monster Libra |
| `TA554` | TH-163 |
| `TEMP.Veles` | XENOTIME |
| `TIDRONE` | — |
| `Taidoor` | Budminer, Earth Aughisky |
| `TeamTNT` | — |
| `The White Company` | — |
| `Threat Group-3390` | Earth Smilodon, TG-3390, Emissary Panda, BRONZE UNION, APT27, Iron Tiger, LuckyMouse, TEMP.Hippo, Budworm, Group 35, ATK 15, Red Phoenix, ZipToken, Iron Taurus |
| `ToddyCat` | — |
| `Tonto Team` | Earth Akhlut, BRONZE HUNTLEY, CactusPete, Karma Panda |
| `Transparent Tribe` | COPPER FIELDSTONE, APT36, Mythic Leopard, ProjectM, TEMP.Lapis, Earth Karkaddan, STEPPY-KAVACH, Green Havildar, APT-C-56, Storm-0156 |
| `Traveling Spider` | GOLD MANSARD, INC, Lynx, Nefilim, Nemty, Nemty X, Nokoyawa |
| `Tropic Trooper` | Pirate Panda, KeyBoy, APT23, Iron, Bronze Hobart, Earth Centaur |
| `Tunnel Spider` | Storm-0216 |
| `Turla` | IRON HUNTER, Group 88, Waterbug, WhiteBear, Snake, Krypton, Venomous Bear, Secret Blizzard, BELUGASTURGEON, SIG2, SIG15, SIG23, CTG-8875, Pacifier APT, ATK 13, ITG12, Makersmark, Popeye, Wraith, TAG-0530, UNC4210, SUMMIT, Pensive Ursa, Blue Python |
| `Twisted Panda` | — |
| `UNC2447` | — |
| `UNC3886` | — |
| `UNC4191` | — |
| `UNC6588` | — |
| `Venom Spider` | Golden Chickens |
| `Veto Spider` | nixploiter |
| `Vice Society` | — |
| `Vice Spider` | Arcane Mantis, DEV-0832, InterLock, Nefarious Mantis, Rhysida, Storm-0300, UNC4120, Vanilla Tempest, Vice Society, Vice Spider |
| `Vicious Panda` | Bronze Dudley |
| `Void Rabisu` | DEV-0978,RomCom,Storm-0978,Tropical Scorpius |
| `Volatile Cedar` | Dancing Salome, DeftTorero, Lebanese Cedar |
| `Volt Typhoon` | BRONZE SILHOUETTE, Vanguard Panda, DEV-0391, UNC3236, Voltzite, Insidious Taurus |
| `WIP26` | — |
| `WIRTE` | WIRTE Group, White Dev 21 |
| `Whitefly` | ATK 83, Bronze Walker, SectorM04, Superman, TEMP.Mimic, Mofang |
| `Winnti Group` | Blackfly, Wicked Panda |
| `Winter Vivern` | TA473, UAC-0114 |
| `Wizard Spider` | UNC1878, TEMP.MixMaster, Grim Spider, FIN12, GOLD BLACKBURN, ITG23, Periwinkle Tempest, DEV-0193, Gold Ulrick |
| `Worok` | - |
| `ZIRCONIUM` | APT31, Violet Typhoon, Judgment Panda, Zirconium, RedBravo, Bronze Vinewood, TA412, Red Keres |
| `menuPass` | Cicada, POTASSIUM, Stone Panda, APT10, Red Apollo, CVNX, HOGFISH, BRONZE RIVERSIDE, menuPass Team, Happyyongzi, CTG-5938, ATK 41, TA429, ITG01, Granite Taurus, Earth Kasha, Cuckoo Spear |
| `xHunt` | SectorD01,Hive0081,Cobalt Katana,Hunter Serpens |
