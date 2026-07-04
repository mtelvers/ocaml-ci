(** A proof-of-work browser challenge, as a Dream middleware.

    A JavaScript-less client requesting a {e protected} path is served an
    interstitial whose embedded JavaScript ([/js/challenge.js]) must find a
    nonce [n] such that [SHA-256(challenge ^ ":" ^ n)] has at least [difficulty]
    leading zero bits; on success it is issued a short HMAC-signed cookie and
    let through. Real browsers solve this transparently in well under a second;
    HTTP-only crawlers never obtain a token. Entirely stateless on the server. *)

type t

val v :
  ?secret:string ->
  ?difficulty:int ->
  ?token_ttl:float ->
  ?challenge_ttl:float ->
  ?cookie_name:string ->
  ?protect:(string -> bool) ->
  unit -> t
(** [v ()] is a challenge configuration.
    @param secret HMAC key. Defaults to 32 random bytes at startup (so tokens
      are invalidated on restart).
    @param difficulty Leading zero bits required of the PoW hash (default 12).
    @param token_ttl Lifetime of an issued token cookie, seconds (default 1 week).
    @param challenge_ttl How long a freshly issued challenge may be solved for,
      seconds (default 10 minutes).
    @param cookie_name Token cookie name (default ["__ocurrent_pow"]).
    @param protect Predicate on the request path; a [`GET] whose path satisfies
      it is challenged (default [fun _ -> false]). Gating by path — not the
      [Accept] header — is deliberate: a crawler cannot spoof it away. *)

val middleware : t -> Dream.middleware
(** [middleware t] gates protected paths and handles the verification endpoint.
    Requests that are not protected (assets, badges, the homepage) and requests
    carrying a valid token pass straight through. *)
