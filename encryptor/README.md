# 3110-final-project
3110 Final Project

Members:
1. Dylan Vig (drv36, drv36@cornell.edu)
2. Joshua George (jjg322, jjg322@cornell.edu)
3. Aitzaz Shaikh (ams845, ams845@cornell.edu)
4. Tina Tewari (tt552, tt552@cornell.edu)
5. Muhammad Hisham (mh2539, mh2539@cornell.edu)


How to run the program:
1) run dune build in the terminal
2) run dune exec bin/main.exe encryptor in terminal
3) Follow the prompts by the program. 

Notes:
- When entering a filename, add data as prefix so for sampleinput1.txt, you'd do data/sampleinput1.txt.
- For Blowfish, use the same key for encryption and decryption. You choose the key as the user but it should be
exactly 8 numerical digits.



SHA3/RC2

ENCRYPT:

select option 3 followed by 1
file name (must end with .txt)
Encrypted file will be saved as: <filename>.txt

DECRYPT:

select option 3 followed by 2
file name (must end with txt.enc)
Decrypted file will be saved as: <filename>.txt.enc
