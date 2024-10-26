(* bin/main.ml *)

(* Function to read a file and return its contents *)
let read_file filename =
  try
    let in_channel = open_in filename in
    let file_content =
      really_input_string in_channel (in_channel_length in_channel)
    in
    close_in in_channel;
    Some file_content
  with Sys_error err ->
    Printf.printf "Error: %s\n" err;
    None

(* Function to ask the user for a file and display its contents *)
let ask_for_file () =
  Printf.printf "Enter the filename containing the message to encrypt: ";
  let filename = read_line () in
  match read_file filename with
  | Some content -> Printf.printf "File content:\n%s\n" content
  | None -> Printf.printf "Failed to read the file.\n"

(* Main function *)
let () = ask_for_file ()
