Collaborators:

Aitzaz:
1) Used Chatgpt for the following:
     -Define function to read file from terminal
     -Find the ocaml equivalent for the ord function in python that converts letter into numbers (message encoding)
     -Write functions to convert string to ASCII codes and backwards
     - help to write the driver's program: a lot of debugging, incorporating infinity case for ecc workflow for pattern matching exhaustiveness (saved time as would not have to understand the whole ECC algorithm which was implemented by my partner), adding gracefully error messages in case of program failure or incorrect inputs, writing to files after running encryption/decryption on it, Scanf scanning module and its usage, final 5 lines of code to get the main() running on command line input, generating examples of each algorithm use case 
     - specifications for rsa.mli file functions

2) Youtube video by NeuralNine which implements RSA in python. Used the python as reference to implement the algorithm in Ocaml

3) Reference for modular inverse function: "https://rosettacode.org/wiki/Modular_inverse#Translation_of:_Haskell"

4) Obtained 1000 word sample essay for sampleinput3.txt from "https://www.customwritings.com/howtowrite/post/1000-words-essay-sample/"



Joshua:
1) Used chatgpt for:
     - defining function to convert between an ascii list and a string in the encryptor test file
     - writing the int_to_binary and binary_to_int functions in blowfish.ml
     - string_to_binary, binary_to_string, and binary_string_to_list in blowfish.ml
     - tracking and adjusting for the amount of padding in encrypt and decrypt
     - Printf.sprintf "%08d" usage
     - in assert_failure tests
     - in encrypt_file_blowfish and decrypt_file_blowfish functions
     - base_data_dir function for data dir paths

2) Blowfish reference: https://jacobfilipp.com/DrDobbs/articles/DDJ/1994/9404/9404d/9404d.htm


Tina: 
1) I used chat gpt for: - ECC test file: ecc_point_addition_inverse_test, ecc_point_addition_associative_test _, ecc_encrypt_decrypt_edge_cases_test _, ecc_scalar_mult_boundary_test _, ecc_point_addition_boundary_test _ - ecc.mli : generate_keys, is_on_curve ..I was having problems with ecc.ml and ecc.mli file matching so gpt helped fix that problem - implementing this into the driver - referred to this

Hisham:

SHA3 Implementation:
1) keecak constants adopted from https://keccak.team/keccak_specs_summary.html
2) Used AI to figure out the syntax mistake in my implementation of read_hex_array and read_int64_array
3) Used AI to help understand implementation of column_parity, theta, and rho offset by prompting it on the maths for understanding and resources on RC2, however implemented myself and
4) Used AI to help figure out my syntax issue in the implementation of Squeeze
5) Used AI to help understand the order of the Mixing Rounds, alongside with the documentation found on the web for RC2.
6) Used AI to write the helper functions in the test file and correct any syntax issues in my implementation to fix the bugs
7) Used AI in encrypt decrypt to resolve type and syntax issue

Dylan:
1) I used ChatGPT to help me learn more about the AES-128 algorithm, as well as to help me develop a rough blueprint for how I wanted to implement it in terms of breaking it up into different helper methods
2) I used multiple online resources to help me learn more about the specifics of implementing the AES-128 algorithm
- https://www.geeksforgeeks.org/advanced-encryption-standard-aes/
- https://www.youtube.com/watch?v=WPz4Kzz6vk4
- https://www.angelfire.com/biz7/atleast/mix_columns.pdf
3) I used ChatGPT to aid me while writing some of the methods for AES-128, especially gmul, mix_columns_generic, key_expansion, aes_encrypt_block, aes_decrypt_block, encrypt_file, and decrypt_file
4) I used ChatGPT to help me generate the necessary CSVs that I needed to use for my algorithm
5) I used ChatGPT to help me write the "test_encrypt_decrypt_file" test
6) I used ChatGPT for a lot of debugging assistance