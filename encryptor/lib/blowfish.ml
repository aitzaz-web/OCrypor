open Csv

let csv_to_array filename =
  Array.of_list
    (List.map
       (fun s -> int_of_string (String.trim s))
       (List.flatten (Csv.load filename)))

let p_array = csv_to_array "../data/p_array.csv"
let s_box_1 = csv_to_array "../data/s1_box.csv"
let s_box_2 = csv_to_array "../data/s2_box.csv"
let s_box_3 = csv_to_array "../data/s3_box.csv"
let s_box_4 = csv_to_array "../data/s4_box.csv"

let int_to_binary n =
  let rec to_binary_list n acc =
    if n = 0 then acc else to_binary_list (n lsr 1) ((n land 1) :: acc)
  in
  let binary = to_binary_list n [] in
  (* Pad the binary list to 32 bits if needed *)
  let padding = List.init (32 - List.length binary) (fun _ -> 0) in
  padding @ binary

let binary_to_int bin_lst =
  List.fold_left (fun acc bit -> (acc lsl 1) lor bit) 0 bin_lst

let xor bin_lst1 bin_lst2 =
  if List.length bin_lst1 <> List.length bin_lst2 then
    invalid_arg "Binary lists must both be length 32."
  else List.map2 (fun l1 l2 -> if l1 = l2 then 0 else 1) bin_lst1 bin_lst2

let init_p_array key =
  let bin_key = int_to_binary key in
  if List.length bin_key <> 32 then invalid_arg "Requires a 64 bit key."
