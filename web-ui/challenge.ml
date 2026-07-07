(* Anubis-style proof-of-work browser challenge, as a Dream middleware.

   Ported from ocurrent's [Current_web.Challenge] (used by opam-repo-ci) to
   Dream, to keep JavaScript-less scraper crawls off the expensive /github/
   pages (each fans out RPC into the engine). Stateless: both the challenge and
   the issued token are HMAC-signed with a per-process secret, so nothing is
   stored server-side. Only paths matched by [protect] are challenged, so
   static assets, badges and the homepage pass untouched. (Prometheus metrics
   are served on a separate port, not through this Dream app.)

   The interstitial's solver ([/js/challenge.js]) and styling
   ([/css/challenge.css]) are ordinary static files served by the router. *)

(* The endpoint the interstitial's JavaScript calls once it has solved the
   proof-of-work. Intercepted by [middleware] before normal routing. *)
let verify_path = "/.ocurrent-challenge/verify"

type t = {
  secret : string;
  difficulty : int;
  token_ttl : float;
  challenge_ttl : float;
  cookie_name : string;
  protect : string -> bool;
}

let v ?secret ?(difficulty = 12) ?(token_ttl = 604800.) ?(challenge_ttl = 600.)
    ?(cookie_name = "__ocurrent_pow") ?(protect = fun _ -> false) () =
  (* [Dream.random] gives cryptographically-secure bytes, so we avoid a direct
     mirage-crypto dependency here. *)
  let secret = match secret with Some s -> s | None -> Dream.random 32 in
  { secret; difficulty; token_ttl; challenge_ttl; cookie_name; protect }

let hmac_hex t msg =
  Digestif.SHA256.hmac_string ~key:t.secret msg |> Digestif.SHA256.to_hex

(* Constant-time string equality (assumes [a] is the trusted-length value). *)
let ct_eq a b =
  if String.length a <> String.length b then false
  else begin
    let acc = ref 0 in
    String.iteri (fun i c -> acc := !acc lor (Char.code c lxor Char.code b.[i])) a;
    !acc = 0
  end

let now () = Unix.time ()

(* "<exp>.<sig>" where sig = HMAC("tok:" ^ exp). *)
let make_token t =
  let exp = Printf.sprintf "%.0f" (now () +. t.token_ttl) in
  exp ^ "." ^ hmac_hex t ("tok:" ^ exp)

let valid_token t s =
  match String.index_opt s '.' with
  | None -> false
  | Some i ->
    let exp = String.sub s 0 i in
    let sg = String.sub s (i + 1) (String.length s - i - 1) in
    ct_eq (hmac_hex t ("tok:" ^ exp)) sg
    && (match float_of_string_opt exp with Some e -> e > now () | None -> false)

(* "<ts>.<sig>" where sig = HMAC("chal:" ^ ts). Binds the challenge to our
   secret and a time, so a client cannot mint its own. *)
let make_challenge t =
  let ts = Printf.sprintf "%.0f" (now ()) in
  ts ^ "." ^ hmac_hex t ("chal:" ^ ts)

let valid_challenge t c =
  match String.index_opt c '.' with
  | None -> false
  | Some i ->
    let ts = String.sub c 0 i in
    let sg = String.sub c (i + 1) (String.length c - i - 1) in
    ct_eq (hmac_hex t ("chal:" ^ ts)) sg
    && (match float_of_string_opt ts with
        | Some t0 -> now () -. t0 <= t.challenge_ttl
        | None -> false)

(* Number of leading zero bits of a raw (binary) string. *)
let leading_zero_bits s =
  let clz_byte b =
    let rec go n = if n = 8 || (b lsr (7 - n)) land 1 = 1 then n else go (n + 1) in
    go 0
  in
  let n = String.length s in
  let rec go i acc =
    if i >= n then acc
    else
      let c = Char.code s.[i] in
      if c = 0 then go (i + 1) (acc + 8) else acc + clz_byte c
  in
  go 0 0

let pow_ok t ~challenge ~nonce =
  let h = Digestif.SHA256.(digest_string (challenge ^ ":" ^ nonce) |> to_raw_string) in
  leading_zero_bits h >= t.difficulty

(* Only allow same-site redirect targets (a local absolute path). *)
let safe_redirect = function
  | Some r
    when String.length r >= 1 && r.[0] = '/'
         && not (String.length r >= 2 && r.[1] = '/')
         && not (String.contains r '\n') && not (String.contains r '\r') ->
    r
  | _ -> "/"

let get_cookie t request =
  match Dream.header request "Cookie" with
  | None -> None
  | Some s ->
    String.split_on_char ';' s
    |> List.find_map (fun kv ->
        match String.index_opt kv '=' with
        | None -> None
        | Some i ->
          let k = String.trim (String.sub kv 0 i) in
          let v = String.sub kv (i + 1) (String.length kv - i - 1) in
          if k = t.cookie_name then Some v else None)

let set_cookie_header t value =
  ("Set-Cookie",
   String.concat "; "
     [ Printf.sprintf "%s=%s" t.cookie_name value;
       "Path=/";
       Printf.sprintf "Max-Age=%d" (int_of_float t.token_ttl);
       "HttpOnly"; "SameSite=Lax"; "Secure" ])

let interstitial_body ~challenge ~difficulty ~redirect =
  Printf.sprintf
    {|<!DOCTYPE html>
<html><head><meta charset="utf-8"/>
<meta name="viewport" content="width=device-width, initial-scale=1.0"/>
<meta name="robots" content="noindex,nofollow"/>
<link rel="stylesheet" href="/css/challenge.css"/>
<title>One moment…</title></head>
<body><div id="challenge" class="challenge" data-challenge="%s" data-difficulty="%d" data-redirect="%s" data-verify="%s">
<h1>Just a moment…</h1>
<p>Your browser is solving a small proof-of-work puzzle to keep automated scrapers out.</p>
<p id="status">Working…</p>
<noscript><p>JavaScript is required to solve the proof-of-work puzzle.</p></noscript>
</div>
<script src="/js/challenge.js"></script></body></html>|}
    (Dream.html_escape challenge) difficulty
    (Dream.html_escape redirect) (Dream.html_escape verify_path)

let respond_interstitial t request =
  let challenge = make_challenge t in
  let redirect = safe_redirect (Some (Dream.target request)) in
  let body = interstitial_body ~challenge ~difficulty:t.difficulty ~redirect in
  (* 503 so crawlers/caches treat it as "not the content"; browsers still run
     the JS and are redirected to the real page once solved. The sentinel
     header stops the app's Dream error_template from overwriting this body
     (Dream funnels every error-status response through it); see
     view/client_error.ml. *)
  Dream.respond ~status:`Service_Unavailable
    ~headers:[ ("Content-Type", "text/html; charset=utf-8");
               ("Cache-Control", "no-store");
               ("X-Ocurrent-Challenge", "1") ]
    body

let respond_verify t request =
  let redirect = safe_redirect (Dream.query request "r") in
  match Dream.query request "c", Dream.query request "n" with
  | Some challenge, Some nonce
    when valid_challenge t challenge && pow_ok t ~challenge ~nonce ->
    Dream.respond ~status:`Found
      ~headers:[ ("Location", redirect);
                 set_cookie_header t (make_token t);
                 ("Cache-Control", "no-store") ]
      ""
  | _ ->
    (* Bad / stale solution: re-issue a fresh challenge. *)
    respond_interstitial t request

let middleware t : Dream.middleware =
 fun inner request ->
  let path, _query = Dream.split_target (Dream.target request) in
  if path = verify_path then respond_verify t request
  else if
    Dream.method_ request = `GET
    && t.protect path
    && (match get_cookie t request with
        | Some tok -> not (valid_token t tok)
        | None -> true)
  then respond_interstitial t request
  else inner request
