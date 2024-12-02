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

let string_to_binary key =
  let char_to_bin c =
    let ascii = Char.code c in
    List.init 8 (fun i -> (ascii lsr (7 - i)) land 1)
  in
  List.flatten (List.map char_to_bin (String.to_seq key |> List.of_seq))

let xor bin_lst1 bin_lst2 =
  if List.length bin_lst1 <> List.length bin_lst2 then
    invalid_arg "Binary lists must both be length 32."
  else List.map2 (fun l1 l2 -> if l1 = l2 then 0 else 1) bin_lst1 bin_lst2

let sub s e list =
  let rec sub_traverse i acc =
    if i >= e then List.rev acc
    else sub_traverse (i + 1) (List.nth list i :: acc)
  in
  sub_traverse s []

let init_p_array key =
  let key_as_binary = string_to_binary (string_of_int key) in
  if List.length key_as_binary <> 64 then
    invalid_arg "The key must be 64 bits long."
  else
    let key_l = sub 0 32 key_as_binary in
    let key_r = sub 32 64 key_as_binary in
    let new_p_array =
      Array.mapi
        (fun i p ->
          let p_as_binary = int_to_binary p in
          let key_half = if i mod 2 = 0 then key_l else key_r in
          binary_to_int (xor p_as_binary key_half))
        p_array
    in
    new_p_array

(**https://jacobfilipp.com/DrDobbs/articles/DDJ/1994/9404/9404d/9404d.htm*)

(**https://www.youtube.com/watch?v=7hP5qEAHP1Y*)
