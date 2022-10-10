%%
%% erlang PIV client
%%
%% Copyright 2020 Alex Wilson <alex@uq.edu.au>, The University of Queensland
%%
%% Redistribution and use in source and binary forms, with or without
%% modification, are permitted provided that the following conditions
%% are met:
%% 1. Redistributions of source code must retain the above copyright
%%    notice, this list of conditions and the following disclaimer.
%% 2. Redistributions in binary form must reproduce the above copyright
%%    notice, this list of conditions and the following disclaimer in the
%%    documentation and/or other materials provided with the distribution.
%%
%% THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
%% IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
%% OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
%% IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
%% INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
%% NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
%% DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
%% THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
%% (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
%% THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
%%

%% @doc An APDU transform which handles commands for the NIST PIV applet
%%      (defined in SP 800-73-4).
-module(nist_piv).

-include("iso7816.hrl").
-include("nist_piv.hrl").

-behaviour(apdu_transform).

-include_lib("public_key/include/public_key.hrl").

-export([
    formats/0,
    init/2,
    begin_transaction/1,
    command/2,
    reply/2,
    end_transaction/1,
    terminate/1
]).

-export([
    algo_for_key/1
    ]).

-export([
    select_reply/2,
    chuid_reply/2,
    discov_reply/2,
    keyhist_reply/2,
    cert_reply/2,
    yk_get_ver_reply/2,
    yk_get_serial_reply/2,
    object_reply/2,
    verify_reply/2,
    clear_reply/2,
    gen_auth_resp_reply/2,
    admin_witness_reply/2,
    admin_chal_reply/2,
    sw_reply/2,
    gen_asym_reply/2,
    yk_metadata_reply/2
]).

-export_type([
    cmd/0, reply/0,
    slot/0,
    obj_tag/0,
    auth_method/0,
    sym_algo/0,
    asym_algo/0,
    sm_algo/0,
    algo/0,
    rts/0, chuid/0, discov/0, keyhist/0, yk_version/0,
    cert/0, pubkey/0,
    guid/0
]).

-type auth_method() :: piv_pin | global_pin | {occ, primary | secondary} |
    piv_puk | pairing_code.
%% Authentication methods.

-type slot() :: symbolic_slot() | numeric_slot().
%% PIV key reference / slot identifier.

-type symbolic_slot() :: piv_auth | piv_sign | piv_card_auth | piv_key_mgmt |
    {retired, integer()}.
%% Slot symbolic identifier

-type numeric_slot() :: integer().
%% Slot number, e.g. <code>16#9A</code>

-type obj_tag() :: cardcap | chuid | secobj | keyhist | printinfo |
    fingerprints | security | facial_image | iris_images | sm_cert_signer |
    pairing_code | bio_group_tpl | discov |
    {cert, symbolic_slot()} | {cert, numeric_slot()} | binary().
%% A PIV object tag, which can be used to obtain its contents.

-type sym_algo() :: des3_ecb | aes128_ecb | aes192_ecb | aes256_ecb.
%% Symmetric key algorithms. Note that <code>des3_ecb</code> is 3-key Triple
%% DES.

-type asym_algo() :: rsa1024 | rsa2048 | eccp256 | eccp384.
%% Asymmetric (public/private) key algorithms.

-type asym_hashoncard_algo() :: eccp256_sha1 | eccp256_sha256 |
    eccp384_sha1 | eccp384_sha256 | eccp384_sha384.
%% Algorithms used by the hash-on-card extension (PIVApplet)

-type sm_algo() :: cs2 | cs7.
%% Algorithms used for secure messaging.

-type algo() :: sym_algo() | asym_algo() | asym_hashoncard_algo() |
    sm_algo().
%% PIV algorithm IDs

-type rts() :: #{version => integer(), uri => binary(),
    app_label => binary(), algorithms => [algo()]}.
%% Decoded information from a response-to-select (RTS).

-type chuid() :: #{fascn => binary(), org_id => binary(),
    duns => binary(), guid => guid(), expiry => binary(),
    chuuid => binary(), signature => binary()}.
%% Decoded information from the CHUID (card holder UID) file.

-type discov() :: #{auth_methods => [auth_method()],
    primary_auth => auth_method(), vci => boolean(),
    pairing_code_for_vci => boolean()}.
%% Decoded information from the PIV Discovery Object.

-type keyhist() :: #{on_card_certs => integer(), off_card_certs => integer(),
    uri => binary()}.
%% Decoded information from the PIV Key History Object.

-type yk_touch_policy() :: default | never | always | cached.
-type yk_pin_policy() :: default | never | once | always.

-type cert() :: #'OTPCertificate'{}.
-type pubkey() :: #'RSAPublicKey'{} | {#'ECPoint'{}, {namedCurve, crypto:ec_named_curve()}}.

-type guid() :: binary().
%% GUID in raw binary form (16 bytes).

-type pin() :: binary().
%% ASCII numeric chars, length 6-8.

-type fixed_len_data() :: binary().
%% Fixed length auth data, already padded if necessary.

-type attempts() :: integer().
%% Count of remaining attempts at an authentication method.

-type yk_version() :: {Major :: integer(), Minor :: integer(),
    Patch :: integer()}.

-type cmd() :: select_cmd() | read_chuid_cmd() | read_discov_cmd() |
    read_keyhist_cmd() | read_cert_cmd() | verify_cmd() | sign_cmd() |
    ecdh_cmd() | admin_auth_cmd() | generate_cmd() | write_cert_cmd() |
    change_pin_cmd() | reset_pin_cmd() |
    yk_ver_cmd() | yk_serial_cmd() | yk_set_mgmt_cmd() | yk_generate_cmd() |
    yk_metadata_cmd().

-type reply() :: select_reply() | read_chuid_reply() | read_discov_reply() |
    read_keyhist_reply() | read_cert_reply() | verify_reply() |
    sign_reply() | ecdh_reply() | admin_auth_reply() | generate_reply() |
    write_cert_reply() | change_pin_reply() | reset_pin_reply() |
    yk_ver_reply() | yk_serial_reply() | yk_set_mgmt_reply() |
    yk_generate_reply() | yk_metadata_reply().

-type select_cmd() :: select.
-type select_reply() :: {ok, rts()} | {error, term()}.

-type read_chuid_cmd() :: read_chuid.
-type read_chuid_reply() :: {ok, chuid()} | {error, term()}.

-type read_discov_cmd() :: read_discov.
-type read_discov_reply() :: {ok, discov()} | {error, term()}.

-type read_keyhist_cmd() :: read_keyhist.
-type read_keyhist_reply() :: {ok, keyhist()} | {error, term()}.

-type read_cert_cmd() :: {read_cert, slot()}.
-type read_cert_reply() :: {ok, cert()} | {error, term()}.

-type verify_cmd() :: {verify, auth_method(), fixed_len_data()} |
    {verify_pin, auth_method(), pin()} | {clear, auth_method()}.
-type verify_reply() :: ok | {error, bad_auth, attempts()} | {error, term()}.

-type change_pin_cmd() :: {change_pin, auth_method(), Old :: pin(), New :: pin()}.
-type change_pin_reply() :: verify_reply().

-type sign_cmd() :: {sign, slot(), algo(), binary()}.
-type sign_reply() :: {ok, binary()} | {error, term()}.

-type ecdh_cmd() :: {ecdh, slot(), algo(), #'ECPoint'{}}.
-type ecdh_reply() :: {ok, binary()} | {error, term()}.

-type generate_cmd() :: {generate, slot(), algo()}.
-type generate_reply() :: {ok, pubkey()} | {error, term()}.

-type write_cert_cmd() :: {write_cert, slot(), cert()}.
-type write_cert_reply() :: ok | {error, term()}.

-type reset_pin_cmd() :: {reset_pin, PUK :: pin(), NewPIN :: pin()}.
-type reset_pin_reply() :: verify_reply().

-type yk_generate_cmd() :: {generate, slot(), algo(), yk_pin_policy(), yk_touch_policy()}.
-type yk_generate_reply() :: generate_reply().

-type yk_ver_cmd() :: yk_get_version.
-type yk_ver_reply() :: {ok, yk_version()} | {error, term()}.

-type yk_serial_cmd() :: yk_get_serial.
-type yk_serial_reply() :: {ok, integer()} | {error, term()}.

-type yk_set_mgmt_cmd() :: {yk_set_mgmt, sym_algo(), binary(), yk_touch_policy()}.
-type yk_set_mgmt_reply() :: ok | {error, term()}.

-type yk_metadata_cmd() :: {yk_get_metadata, slot() | auth_method()}.
-type yk_metadata_reply() :: {ok, yk_metadata()} | {error, term()}.

-type yk_metadata() :: yk_metadata_asym() | yk_metadata_sym() | yk_metadata_pin().
-type yk_metadata_asym() :: #{
    algo => algo(),
    pin_policy => yk_pin_policy(),
    touch_policy => yk_touch_policy(),
    origin => imported | generated,
    public_key => pubkey()
    }.
-type yk_metadata_sym() :: #{
    algo => algo(),
    pin_policy => yk_pin_policy(),
    touch_policy => yk_touch_policy(),
    default => boolean()
    }.
-type yk_metadata_pin() :: #{
    default => boolean(),
    retries => {Max :: integer(), Remaining :: integer()}
    }.

-type admin_auth_cmd() :: {admin_auth, sym_algo(), binary()}.
-type admin_auth_reply() :: ok | {error, term()}.

-type init_opts() :: #{
    gzip_certificates => boolean()
    }.

-record(?MODULE, {
    opts :: init_opts(),
    handler :: atom(),
    objmap :: iso7816:tlv_map(),
    gen_algo :: asym_algo(),
    admin_algo :: undefined | sym_algo(),
    admin_key :: undefined | binary(),
    admin_chal :: undefined | binary(),
    clear_auth :: undefined | auth_method(),
    used_creds = #{} :: #{auth_method() => true}
}).

%% @private
formats() -> {piv, xapdu}.

%% @private
init(_Proto, []) ->
    {ok, #?MODULE{opts = #{}}};
init(_Proto, [Opts]) ->
    {ok, #?MODULE{opts = Opts}}.

%% @private
terminate(#?MODULE{}) ->
    ok.

%% @private
begin_transaction(S = #?MODULE{}) ->
    {ok, S}.

%% @private
end_transaction(S = #?MODULE{used_creds = CredMap}) ->
    case maps:size(CredMap) of
        0 -> {ok, S};
        _ -> {ok, reset, S#?MODULE{used_creds = #{}}}
    end.

cmd_apdu(get_data, P1, P2, Map) ->
    cmd_apdu(get_data, P1, P2, Map, ?PIV_GET_DATA_INVTAGMAP);
cmd_apdu(general_auth, P1, P2, Map) ->
    cmd_apdu(general_auth, P1, P2, Map, ?PIV_GEN_AUTH_INVTAGMAP);
cmd_apdu(generate_asym_key, P1, P2, Map) ->
    cmd_apdu(generate_asym_key, P1, P2, Map, ?PIV_GEN_ASYM_INVTAGMAP).

cmd_apdu(Ins, P1, P2, Map, TagMap) ->
    Data = iso7816:encode_ber_tlvs_map(Map, TagMap),
    #apdu_cmd{cla = iso, ins = Ins, p1 = P1, p2 = P2, data = Data, le = 0}.

%% @private
-spec command(cmd(), #?MODULE{}) -> {ok, [term()], #?MODULE{}}.
command(select, S0 = #?MODULE{}) ->
    A = #apdu_cmd{cla = iso, ins = select, p1 = 4, p2 = 0,
        data = <<?PIV_AID>>, le = 0},
    {ok, [A], S0#?MODULE{handler = select_reply}};

command(read_chuid, S0 = #?MODULE{}) ->
    A = cmd_apdu(get_data, 16#3F, 16#FF, #{tag => encode_tag(chuid)}),
    {ok, [A], S0#?MODULE{handler = chuid_reply}};

command(read_discov, S0 = #?MODULE{}) ->
    A = cmd_apdu(get_data, 16#3F, 16#FF, #{tag => encode_tag(discov)}),
    {ok, [A], S0#?MODULE{handler = discov_reply}};

command(read_keyhist, S0 = #?MODULE{}) ->
    A = cmd_apdu(get_data, 16#3F, 16#FF, #{tag => encode_tag(keyhist)}),
    {ok, [A], S0#?MODULE{handler = keyhist_reply}};

command({read_object, Tag}, S0 = #?MODULE{}) ->
    A = cmd_apdu(get_data, 16#3F, 16#ff, #{tag => encode_tag(Tag)}),
    Map = case Tag of
        cardcap -> ?PIV_CARDCAP_TAGMAP;
        printinfo -> ?PIV_PRINTINFO_TAGMAP;
        _ -> #{16#53 => value}
    end,
    {ok, [A], S0#?MODULE{handler = object_reply, objmap = Map}};

command({write_object, Tag, MapOrData}, S0 = #?MODULE{}) ->
    TagMap = case Tag of
        chuid -> ?PIV_CHUID_INVTAGMAP;
        cardcap -> ?PIV_CARDCAP_INVTAGMAP;
        printinfo -> ?PIV_PRINTINFO_INVTAGMAP;
        keyhist -> ?PIV_KEYHIST_INVTAGMAP;
        _ -> [ {tag, 16#5C}, {value, 16#53} ]
    end,
    M = #{value => MapOrData, tag => encode_tag(Tag)},
    A = cmd_apdu(put_data, 16#3F, 16#FF, M, TagMap),
    {ok, [A], S0#?MODULE{handler = sw_reply}};

command({read_cert, Slot}, S0 = #?MODULE{}) ->
    Tag = {cert, Slot},
    A = cmd_apdu(get_data, 16#3F, 16#ff, #{tag => encode_tag(Tag)}),
    {ok, [A], S0#?MODULE{handler = cert_reply}};

command({write_cert, Slot, Cert}, S0 = #?MODULE{opts = Opts}) ->
    Tag = {cert, Slot},
    RawData = case Cert of
        #'OTPCertificate'{} ->
            public_key:pkix_encode('OTPCertificate', Cert, otp);
        #'Certificate'{} ->
            public_key:pkix_encode('Certificate', Cert, plain)
    end,
    % Yubico's PIV implementation doesn't seem to support gzip certs very well
    % So this is off by default.
    GzipEnable = maps:get(gzip_certificates, Opts, false),
    ZippedData = zlib:gzip(RawData),
    V = if
        GzipEnable and (byte_size(ZippedData) < byte_size(RawData)) ->
            #{ cert => ZippedData, cert_info => <<0:5, 0:1, 1:2>>, lrc => <<>> };
        true ->
            #{ cert => RawData, cert_info => <<0:5, 0:1, 0:2>>, lrc => <<>> }
    end,
    M = #{
        tag => encode_tag(Tag),
        value => V
    },
    A = cmd_apdu(put_data, 16#3F, 16#FF, M, ?PIV_CERT_INVTAGMAP),
    {ok, [A], S0#?MODULE{handler = sw_reply}};

command({verify_pin, Auth, Data0}, S0 = #?MODULE{}) ->
    Data1 = pad_with(Data0, 8, 16#FF),
    command({verify, Auth, Data1}, S0);

command({verify, Auth, Data}, S0 = #?MODULE{used_creds = C0}) ->
    A = #apdu_cmd{cla = iso, ins = verify, p1 = 16#00, p2 = encode_auth(Auth),
        data = Data, le = none},
    C1 = C0#{Auth => true},
    {ok, [A], S0#?MODULE{handler = verify_reply, used_creds = C1}};

command({clear, Auth}, S0 = #?MODULE{}) ->
    A = #apdu_cmd{cla = iso, ins = verify, p1 = 16#FF, p2 = encode_auth(Auth),
        data = none, le = none},
    {ok, [A], S0#?MODULE{handler = clear_reply, clear_auth = Auth}};

command({change_pin, Auth, CurPIN0, NewPIN0}, S0 = #?MODULE{used_creds = C0}) ->
    CurPIN1 = pad_with(CurPIN0, 8, 16#FF),
    NewPIN1 = pad_with(NewPIN0, 8, 16#FF),
    Data = <<CurPIN1/binary, NewPIN1/binary>>,
    A = #apdu_cmd{cla = iso, ins = change_ref_data, p1 = 16#00,
        p2 = encode_auth(Auth), data = Data, le = none},
    C1 = C0#{Auth => true},
    {ok, [A], S0#?MODULE{handler = verify_reply, used_creds = C1}};

command({reset_pin, PUK0, NewPIN0}, S0 = #?MODULE{used_creds = C0}) ->
    PUK1 = pad_with(PUK0, 8, 16#FF),
    NewPIN1 = pad_with(NewPIN0, 8, 16#FF),
    Data = <<PUK1/binary, NewPIN1/binary>>,
    A = #apdu_cmd{cla = iso, ins = reset_retry_counter, p1 = 16#00,
        p2 = encode_auth(piv_pin), data = Data, le = none},
    C1 = C0#{piv_puk => true, piv_pin => true},
    {ok, [A], S0#?MODULE{handler = verify_reply, used_creds = C1}};

command({sign, Slot, Algo, DataOrHash}, S0 = #?MODULE{}) ->
    M = #{
        general_auth => #{
            response => <<>>,
            challenge => DataOrHash
        }
    },
    A = cmd_apdu(general_auth, encode_alg(Algo), encode_slot(Slot), M),
    {ok, [A], S0#?MODULE{handler = gen_auth_resp_reply}};

command({ecdh, Slot, Algo, PartnerKey}, S0 = #?MODULE{}) ->
    #'ECPoint'{point = KD} = PartnerKey,
    <<4, _/binary>> = KD,
    M = #{
        general_auth => #{
            response => <<>>,
            exp => KD
        }
    },
    A = cmd_apdu(general_auth, encode_alg(Algo), encode_slot(Slot), M),
    {ok, [A], S0#?MODULE{handler = gen_auth_resp_reply}};

command({admin_auth, Algo, Key}, S0 = #?MODULE{}) ->
    M = #{
        general_auth => #{
            witness => <<>>
        }
    },
    A = cmd_apdu(general_auth, encode_alg(Algo), 16#9B, M),
    {ok, [A], S0#?MODULE{handler = admin_witness_reply,
        admin_key = Key, admin_algo = Algo}};

command({generate, Slot, Algo}, S0 = #?MODULE{}) ->
    M = #{
        gen_asym => #{
            algo => << (encode_alg(Algo)) >>
        }
    },
    A = cmd_apdu(generate_asym_key, 0, encode_slot(Slot), M),
    {ok, [A], S0#?MODULE{gen_algo = Algo, handler = gen_asym_reply}};

command({generate, Slot, Algo, PinPol, TouchPol}, S0 = #?MODULE{}) ->
    M = #{
        gen_asym => #{
            algo => << (encode_alg(Algo)) >>,
            yk_pin_policy => << (encode_pin_policy(PinPol)) >>,
            yk_touch_policy => << (encode_touch_policy(TouchPol)) >>
        }
    },
    A = cmd_apdu(generate_asym_key, 0, encode_slot(Slot), M),
    {ok, [A], S0#?MODULE{gen_algo = Algo, handler = gen_asym_reply}};

command(yk_get_version, S0 = #?MODULE{}) ->
    A = #apdu_cmd{ins = ?INS_YK_GET_VER, p1 = 0, p2 = 0, data = none, le = 0},
    {ok, [A], S0#?MODULE{handler = yk_get_ver_reply}};

command(yk_get_serial, S0 = #?MODULE{}) ->
    A = #apdu_cmd{ins = ?INS_YK_GET_SERIAL, p1 = 0, p2 = 0,
        data = none, le = 0},
    {ok, [A], S0#?MODULE{handler = yk_get_serial_reply}};

command({yk_get_metadata, SlotOrAuth}, S0 = #?MODULE{}) ->
    A = #apdu_cmd{ins = ?INS_YK_GET_METADATA, p1 = 0,
        p2 = encode_slot_or_auth(SlotOrAuth),
        data = none, le = 0},
    {ok, [A], S0#?MODULE{handler = yk_metadata_reply}};

command({yk_set_mgmt, Algo, Key, TouchPol}, S0 = #?MODULE{}) ->
    D = << (encode_alg(Algo)), 16#9B, (byte_size(Key)),
           Key/binary >>,
    A = #apdu_cmd{cla = iso, ins = ?INS_YK_SET_MGMT, p1 = 16#FF,
        p2 = encode_touch_policy_p2(TouchPol), data = D},
    {ok, [A], S0#?MODULE{handler = sw_reply}}.

%% @private
-spec reply(term(), #?MODULE{}) -> {ok, [reply()], #?MODULE{}}.
reply(R0 = #apdu_reply{}, #?MODULE{handler = undefined}) ->
    error({unexpected_reply, R0});
reply(R0 = #apdu_reply{}, S0 = #?MODULE{handler = H}) ->
    ?MODULE:H(R0, S0).

%% @private
select_reply(#apdu_reply{sw = ok, data = D}, S0 = #?MODULE{}) ->
    {ok, #{apt := Apt}} = iso7816:decode_ber_tlvs_map(D, ?PIV_APT_TAGMAP),
    #{aid := AidSuffix} = Apt,
    case AidSuffix of
        <<?PIV_PIX, Version:16/little>> -> ok;
        <<?PIV_AID, Version:16/little>> -> ok
    end,
    case Apt of
        #{alloc_auth := #{aid := AllocAid}} ->
            case AllocAid of
                <<?NIST_RID>> -> ok;
                <<?PIV_AID>> -> ok;
                <<?PIV_AID, V2:16/little>> when V2 =:= Version -> ok
            end;
        _ -> ok
    end,
    Algs = case Apt of
        #{algos := AlgoTags = [ #{algo := _} | _ ]} ->
            lists:flatten([ [ decode_alg(N) || <<N>> <- AlgBinList ] ||
                #{algo := AlgBinList} <- AlgoTags ]);
        _ ->
            []
    end,
    Base = maps:filter(fun
        (app_label, _) -> true;
        (uri, _) -> true;
        (_, _) -> false
    end, Apt),
    Ret = Base#{ version => Version, algorithms => Algs },
    {ok, [{ok, Ret}], S0#?MODULE{handler = undefined}};
select_reply(#apdu_reply{sw = Other}, S0 = #?MODULE{}) ->
    {ok, [Other], S0#?MODULE{handler = undefined}}.

%% @private
chuid_reply(#apdu_reply{sw = ok, data = D}, S0 = #?MODULE{}) when is_binary(D) ->
    {ok, #{value := V}} = iso7816:decode_ber_tlvs_map(D, ?PIV_CHUID_TAGMAP),
    {ok, [{ok, V}], S0#?MODULE{handler = undefined}};
chuid_reply(#apdu_reply{sw = Other}, S0 = #?MODULE{}) ->
    {ok, [Other], S0#?MODULE{handler = undefined}}.

%% @private
discov_reply(#apdu_reply{sw = ok, data = D}, S0 = #?MODULE{}) when is_binary(D) ->
    {ok, #{value := V}} = iso7816:decode_ber_tlvs_map(D, ?PIV_DISCOV_TAGMAP),
    #{aid := <<?PIV_AID, _Version:16>>} = V,
    #{pinpol := PinPolBin} = V,
    Ret = decode_pinpol(PinPolBin),
    {ok, [{ok, Ret}], S0#?MODULE{handler = undefined}};
discov_reply(#apdu_reply{sw = Other}, S0 = #?MODULE{}) ->
    {ok, [Other], S0#?MODULE{handler = undefined}}.

%% @private
keyhist_reply(#apdu_reply{sw = ok, data = D}, S0 = #?MODULE{}) when is_binary(D) ->
    {ok, #{value := V}} = iso7816:decode_ber_tlvs_map(D, ?PIV_KEYHIST_TAGMAP),
    Ret = maps:map(fun
        (on_card_certs, <<N>>) -> N;
        (off_card_certs, <<N>>) -> N;
        (_K, KV) -> KV
    end, V),
    {ok, [{ok, Ret}], S0#?MODULE{handler = undefined}};
keyhist_reply(#apdu_reply{sw = Other}, S0 = #?MODULE{}) ->
    {ok, [Other], S0#?MODULE{handler = undefined}}.

%% @private
object_reply(#apdu_reply{sw = ok, data = D}, S0 = #?MODULE{objmap = Map}) when is_binary(D) ->
    {ok, #{value := V}} = iso7816:decode_ber_tlvs_map(D, Map),
    {ok, [{ok, V}], S0#?MODULE{handler = undefined}};
object_reply(#apdu_reply{sw = Other}, S0 = #?MODULE{}) ->
    {ok, [Other], S0#?MODULE{handler = undefined}}.

%% @private
cert_reply(#apdu_reply{sw = ok, data = D}, S0 = #?MODULE{}) when is_binary(D) ->
    {ok, #{value := V}} = iso7816:decode_ber_tlvs_map(D, ?PIV_CERT_TAGMAP),
    Rep = case (catch decode_cert(V)) of
        {'EXIT', Reason} -> {error, {decode_error, Reason}};
        Other -> {ok, Other}
    end,
    {ok, [Rep], S0#?MODULE{handler = undefined}};
cert_reply(#apdu_reply{sw = Other}, S0 = #?MODULE{}) ->
    {ok, [Other], S0#?MODULE{handler = undefined}}.

%% @private
gen_auth_resp_reply(#apdu_reply{sw = ok, data = D}, S0 = #?MODULE{}) ->
    {ok, M} = iso7816:decode_ber_tlvs_map(D, ?PIV_GEN_AUTH_TAGMAP),
    #{general_auth := #{response := Sig}} = M,
    {ok, [{ok, Sig}], S0#?MODULE{handler = undefined}};
gen_auth_resp_reply(#apdu_reply{sw = {error, p1p2}}, S0 = #?MODULE{}) ->
    {ok, [{error, bad_slot_or_alg}], S0#?MODULE{handler = undefined}};
gen_auth_resp_reply(#apdu_reply{sw = Err}, S0 = #?MODULE{}) ->
    {ok, [Err], S0#?MODULE{handler = undefined}}.

%% @private
admin_witness_reply(#apdu_reply{sw = ok, data = D}, S0 = #?MODULE{}) ->
    #?MODULE{admin_key = Key, admin_algo = Algo, used_creds = C0} = S0,
    {ok, M} = iso7816:decode_ber_tlvs_map(D, ?PIV_GEN_AUTH_TAGMAP),
    #{general_auth := #{witness := Witness}} = M,
    DecWitness = case Algo of
        des3_ecb ->
            IV = <<0:64>>,
            crypto:crypto_one_time(des_ede3_cbc, Key, IV, Witness,
                [{encrypt, false}]);
        aes128_ecb ->
            IV = <<0:128>>,
            crypto:crypto_one_time(aes_128_cbc, Key, IV, Witness,
                [{encrypt, false}])
    end,
    Challenge = case Algo of
        des3_ecb -> crypto:strong_rand_bytes(8);
        aes128_ecb -> crypto:strong_rand_bytes(16)
    end,
    AM = #{
        general_auth => #{
            witness => DecWitness,
            challenge => Challenge,
            response => <<>>
        }
    },
    A = cmd_apdu(general_auth, encode_alg(Algo), 16#9B, AM),
    C1 = C0#{admin => true},
    {ok, [A], [], S0#?MODULE{admin_chal = Challenge,
        handler = admin_chal_reply, used_creds = C1}};
admin_witness_reply(#apdu_reply{sw = {error, p1p2}}, S0 = #?MODULE{}) ->
    {ok, [{error, bad_slot_or_alg}], S0#?MODULE{handler = undefined,
        admin_key = undefined}};
admin_witness_reply(#apdu_reply{sw = Err}, S0 = #?MODULE{}) ->
    {ok, [Err], S0#?MODULE{handler = undefined, admin_key = undefined}}.

%% @private
admin_chal_reply(#apdu_reply{sw = ok, data = D}, S0 = #?MODULE{}) ->
    #?MODULE{admin_key = Key, admin_algo = Algo, admin_chal = Chal} = S0,
    {ok, M} = iso7816:decode_ber_tlvs_map(D, ?PIV_GEN_AUTH_TAGMAP),
    #{general_auth := #{response := Response}} = M,
    EncChal = case Algo of
        des3_ecb ->
            IV = <<0:64>>,
            crypto:crypto_one_time(des_ede3_cbc, Key, IV, Chal,
                [{encrypt, true}]);
        aes128_ecb ->
            IV = <<0:128>>,
            crypto:crypto_one_time(aes_128_cbc, Key, IV, Chal,
                [{encrypt, true}])
    end,
    S1 = S0#?MODULE{admin_key = undefined, admin_chal = undefined,
        handler = undefined},
    if
        (EncChal =:= Response) ->
            {ok, [ok], S1};
        true ->
            {ok, [{error, bad_response}], S1}
    end;
admin_chal_reply(#apdu_reply{sw = {error, p1p2}}, S0 = #?MODULE{}) ->
    {ok, [{error, bad_slot_or_alg}], S0#?MODULE{handler = undefined,
        admin_key = undefined}};
admin_chal_reply(#apdu_reply{sw = Err}, S0 = #?MODULE{}) ->
    {ok, [Err], S0#?MODULE{handler = undefined, admin_key = undefined}}.

%% @private
gen_asym_reply(#apdu_reply{sw = ok, data = D}, S0 = #?MODULE{}) ->
    {ok, M} = iso7816:decode_ber_tlvs_map(D, ?PIV_GEN_ASYM_TAGMAP),
    #{asym_keypair := KeyInfo} = M,
    Key = case KeyInfo of
        #{modulus := M, public_exp := E} ->
            #'RSAPublicKey'{modulus = binary:decode_unsigned(M),
                publicExponent = binary:decode_unsigned(E)};
        #{ec_point := P} ->
            Curve = case S0 of
                #?MODULE{gen_algo = eccp256} -> prime256v1;
                #?MODULE{gen_algo = eccp384} -> secp384r1
            end,
            {#'ECPoint'{point = P}, {namedCurve, Curve}}
    end,
    {ok, [{ok, Key}], S0#?MODULE{handler = undefined}};
gen_asym_reply(#apdu_reply{sw = Err}, S0 = #?MODULE{}) ->
    {ok, [Err], S0#?MODULE{handler = undefined, admin_key = undefined}}.

%% @private
yk_get_ver_reply(#apdu_reply{sw = ok, data = none}, S0 = #?MODULE{}) ->
    {ok, [{error, not_supported}], S0#?MODULE{handler = undefined}};
yk_get_ver_reply(#apdu_reply{sw = ok, data = D}, S0 = #?MODULE{}) ->
    <<A, B, C>> = D,
    {ok, [{ok, {A, B, C}}], S0#?MODULE{handler = undefined}};
yk_get_ver_reply(#apdu_reply{sw = Other}, S0 = #?MODULE{}) ->
    {ok, [Other], S0#?MODULE{handler = undefined}}.

%% @private
yk_get_serial_reply(#apdu_reply{sw = ok, data = none}, S0 = #?MODULE{}) ->
    {ok, [{error, not_supported}], S0#?MODULE{handler = undefined}};
yk_get_serial_reply(#apdu_reply{sw = ok, data = D}, S0 = #?MODULE{}) ->
    <<Serial:32/big>> = D,
    {ok, [{ok, Serial}], S0#?MODULE{handler = undefined}};
yk_get_serial_reply(#apdu_reply{sw = Other}, S0 = #?MODULE{}) ->
    {ok, [Other], S0#?MODULE{handler = undefined}}.

%% @private
verify_reply(#apdu_reply{sw = ok}, S0 = #?MODULE{}) ->
    {ok, [ok], S0#?MODULE{handler = undefined}};
verify_reply(#apdu_reply{sw = {counter, N}}, S0 = #?MODULE{}) ->
    {ok, [{error, bad_auth, N}], S0#?MODULE{handler = undefined}};
verify_reply(#apdu_reply{sw = Other}, S0 = #?MODULE{}) ->
    {ok, [Other], S0#?MODULE{handler = undefined}}.

%% @private
clear_reply(#apdu_reply{sw = ok}, S0 = #?MODULE{used_creds = C0}) ->
    #?MODULE{clear_auth = Auth} = S0,
    C1 = maps:delete(Auth, C0),
    {ok, [ok], S0#?MODULE{handler = undefined,
                          used_creds = C1,
                          clear_auth = undefined}};
clear_reply(#apdu_reply{sw = Other}, S0 = #?MODULE{}) ->
    {ok, [Other], S0#?MODULE{handler = undefined, clear_auth = undefined}}.

%% @private
yk_metadata_reply(#apdu_reply{sw = ok, data = none}, S0 = #?MODULE{}) ->
    {ok, [{error, not_supported}], S0#?MODULE{handler = undefined}};
yk_metadata_reply(#apdu_reply{sw = ok, data = D}, S0 = #?MODULE{}) ->
    {ok, M} = iso7816:decode_ber_tlvs_map(D, ?YKPIV_MDATA_TAGMAP),
    MData0 = case M of
        #{algo := <<16#FF>>} -> #{};
        #{algo := <<AlgNum>>} -> #{algo => decode_alg(AlgNum)}
    end,
    MData1 = case M of
        #{policy := <<PinPol,TouchPol>>} ->
            MData0#{pin_policy => decode_pin_policy(PinPol),
                    touch_policy => decode_touch_policy(TouchPol)};
        _ -> MData0
    end,
    MData2 = case M of
        #{origin := <<1>>} -> MData1#{origin => generated};
        #{origin := <<2>>} -> MData1#{origin => imported};
        _ -> MData1
    end,
    MData3 = case M of
        #{default := <<1>>} -> MData2#{default => true};
        #{default := <<0>>} -> MData2#{default => false};
        _ -> MData2
    end,
    MData4 = case M of
        #{retries := <<Max, Rem>>} -> MData3#{retries => {Max, Rem}};
        _ -> MData3
    end,
    MData5 = case M of
        #{public := KeyInfo} ->
            Key = case KeyInfo of
                #{modulus := M, public_exp := E} ->
                    #'RSAPublicKey'{modulus = binary:decode_unsigned(M),
                        publicExponent = binary:decode_unsigned(E)};
                #{ec_point := P} ->
                    Curve = case MData4 of
                        #{algo := eccp256} -> prime256v1;
                        #{algo := eccp384} -> secp384r1
                    end,
                    {#'ECPoint'{point = P}, {namedCurve, Curve}}
            end,
            MData4#{public_key => Key};
        _ -> MData4
    end,
    {ok, [{ok, MData5}], S0#?MODULE{handler = undefined}};
yk_metadata_reply(#apdu_reply{sw = Other}, S0 = #?MODULE{}) ->
    {ok, [Other], S0#?MODULE{handler = undefined}}.

%% @private
sw_reply(#apdu_reply{sw = Sw}, S0 = #?MODULE{}) ->
    {ok, [Sw], S0#?MODULE{handler = undefined}}.

decode_pinpol(PinPolBytes) ->
    <<_:1, PivPIN:1, GlobalPIN:1, OCC:1, VCI:1, NoPairing:1, _:2,
      PrimaryPIN>> = PinPolBytes,
    Methods = case PivPIN of 0 -> []; 1 -> [piv_pin] end ++
        case GlobalPIN of 0 -> []; 1 -> [global_pin] end ++
        case OCC of 0 -> []; 1 -> [occ] end,
    R1 = #{auth_methods => Methods},
    R2 = case VCI of
        1 -> case NoPairing of
            1 -> R1#{vci => true, pairing_code_for_vci => false};
            0 -> R1#{vci => true, pairing_code_for_vci => true}
        end;
        0 -> R1#{vci => false}
    end,
    _R3 = case {GlobalPIN, PrimaryPIN} of
        {0, _} -> R2;
        {1, 16#10} -> R2#{primary_auth => piv_pin};
        {1, 16#20} -> R2#{primary_auth => global_pin}
    end.

decode_cert(Map) ->
    CompType = case Map of
        #{cert_info := <<_:5, 0:1, 0:2>>} -> none;
        #{cert_info := <<_:5, 0:1, 1:2>>} -> gzip;
        _ -> none
    end,
    #{cert := CertData} = Map,
    PlainCertData = case CompType of
        none -> CertData;
        gzip -> zlib:gunzip(CertData)
    end,
    public_key:pkix_decode_cert(PlainCertData, otp).

-spec decode_alg(integer()) -> algo().
decode_alg(16#00) -> des3_ecb;
decode_alg(16#03) -> des3_ecb;
decode_alg(16#06) -> rsa1024;
decode_alg(16#07) -> rsa2048;
decode_alg(16#08) -> aes128_ecb;
decode_alg(16#0a) -> aes192_ecb;
decode_alg(16#0c) -> aes256_ecb;
decode_alg(16#11) -> eccp256;
decode_alg(16#14) -> eccp384;
decode_alg(16#27) -> cs2;
decode_alg(16#2E) -> cs7;
decode_alg(16#F0) -> eccp256_sha1;
decode_alg(16#F1) -> eccp256_sha256;
decode_alg(16#F2) -> eccp384_sha1;
decode_alg(16#F3) -> eccp384_sha256;
decode_alg(16#F4) -> eccp384_sha384.

-spec encode_tag(obj_tag()) -> binary().
encode_tag(cardcap) ->          <<16#5F, 16#C1, 16#07>>;
encode_tag(chuid) ->            <<16#5F, 16#C1, 16#02>>;
encode_tag(secobj) ->           <<16#5F, 16#C1, 16#06>>;
encode_tag(keyhist) ->          <<16#5F, 16#C1, 16#0C>>;
encode_tag(printinfo) ->        <<16#5F, 16#C1, 16#09>>;
encode_tag(fingerprints) ->     <<16#5F, 16#C1, 16#03>>;
encode_tag(security) ->         <<16#5F, 16#C1, 16#06>>;
encode_tag(facial_image) ->     <<16#5F, 16#C1, 16#08>>;
encode_tag(iris_images) ->      <<16#5F, 16#C1, 16#21>>;
encode_tag(sm_cert_signer) ->   <<16#5F, 16#C1, 16#22>>;
encode_tag(pairing_code) ->     <<16#5F, 16#C1, 16#23>>;

encode_tag(bio_group_tpl) ->    <<16#7F, 16#61>>;
encode_tag(discov) ->           <<16#7E>>;

encode_tag({cert, piv_auth}) -> encode_tag({cert, 16#9A});
encode_tag({cert, piv_sign}) -> encode_tag({cert, 16#9C});
encode_tag({cert, piv_card_auth}) -> encode_tag({cert, 16#9E});
encode_tag({cert, piv_key_mgmt}) -> encode_tag({cert, 16#9D});
encode_tag({cert, {retired, N}}) -> encode_tag({cert, 16#81 + N});

encode_tag({cert, 16#9A}) -> <<16#5F, 16#C1, 16#05>>;
encode_tag({cert, 16#9C}) -> <<16#5F, 16#C1, 16#0A>>;
encode_tag({cert, 16#9D}) -> <<16#5F, 16#C1, 16#0B>>;
encode_tag({cert, 16#9E}) -> <<16#5F, 16#C1, 16#01>>;
encode_tag({cert, I}) when (I >= 16#82) and (I =< 16#95) ->
    <<16#5F, 16#C1, (16#0D + (I - 16#82))>>;

encode_tag(B) when is_binary(B) -> B.

-spec encode_auth(auth_method()) -> integer().
encode_auth(piv_pin) -> 16#80;
encode_auth(global_pin) -> 16#00;
encode_auth(piv_puk) -> 16#81;
encode_auth({occ, primary}) -> 16#96;
encode_auth({occ, secondary}) -> 16#97;
encode_auth(pairing_code) -> 16#98.

-spec encode_alg(algo()) -> integer().
encode_alg(des3_ecb) -> 16#03;
encode_alg(rsa1024) -> 16#06;
encode_alg(rsa2048) -> 16#07;
encode_alg(aes128_ecb) -> 16#08;
encode_alg(aes192_ecb) -> 16#0a;
encode_alg(aes256_ecb) -> 16#0c;
encode_alg(eccp256) -> 16#11;
encode_alg(eccp384) -> 16#14;
encode_alg(cs2) -> 16#27;
encode_alg(cs7) -> 16#2E;
encode_alg(eccp256_sha1) -> 16#F0;
encode_alg(eccp256_sha256) -> 16#F1;
encode_alg(eccp384_sha1) -> 16#F2;
encode_alg(eccp384_sha256) -> 16#F3;
encode_alg(eccp384_sha384) -> 16#F4.

-spec encode_slot(slot()) -> integer().
encode_slot(piv_auth) -> 16#9A;
encode_slot(piv_sign) -> 16#9C;
encode_slot(piv_card_auth) -> 16#9E;
encode_slot(piv_key_mgmt) -> 16#9D;
encode_slot({retired, N}) -> 16#81 + N;
encode_slot(I) when is_integer(I) -> I.

-spec encode_slot_or_auth(slot() | auth_method()) -> integer().
encode_slot_or_auth(piv_auth) -> 16#9A;
encode_slot_or_auth(piv_sign) -> 16#9C;
encode_slot_or_auth(piv_card_auth) -> 16#9E;
encode_slot_or_auth(piv_key_mgmt) -> 16#9D;
encode_slot_or_auth({retired, N}) -> 16#81 + N;
encode_slot_or_auth(piv_pin) -> 16#80;
encode_slot_or_auth(global_pin) -> 16#00;
encode_slot_or_auth(piv_puk) -> 16#81;
encode_slot_or_auth({occ, primary}) -> 16#96;
encode_slot_or_auth({occ, secondary}) -> 16#97;
encode_slot_or_auth(pairing_code) -> 16#98;
encode_slot_or_auth(I) when is_integer(I) -> I.

-spec encode_touch_policy_p2(yk_touch_policy()) -> integer().
encode_touch_policy_p2(default) -> 16#FF;
encode_touch_policy_p2(never) -> 16#FF;
encode_touch_policy_p2(always) -> 16#FE;
encode_touch_policy_p2(cached) -> error({unsupported_touch_policy, cached}).

-spec encode_touch_policy(yk_touch_policy()) -> integer().
encode_touch_policy(default) -> 16#00;
encode_touch_policy(never) -> 16#01;
encode_touch_policy(always) -> 16#02;
encode_touch_policy(cached) -> 16#03.

-spec encode_pin_policy(yk_pin_policy()) -> integer().
encode_pin_policy(default) -> 16#00;
encode_pin_policy(never) -> 16#01;
encode_pin_policy(once) -> 16#02;
encode_pin_policy(always) -> 16#03.

-spec decode_touch_policy(integer()) -> yk_touch_policy().
decode_touch_policy(16#00) -> default;
decode_touch_policy(16#01) -> never;
decode_touch_policy(16#02) -> always;
decode_touch_policy(16#03) -> cached.

-spec decode_pin_policy(integer()) -> yk_pin_policy().
decode_pin_policy(16#00) -> default;
decode_pin_policy(16#01) -> never;
decode_pin_policy(16#02) -> once;
decode_pin_policy(16#03) -> always.

pad_with(Data0, Len, PadByte) ->
    PaddingLen = Len - byte_size(Data0),
    Padding = binary:copy(<<PadByte>>, PaddingLen),
    <<Data0/binary, Padding/binary>>.

-spec algo_for_key(pubkey()) -> algo().
algo_for_key(#'RSAPublicKey'{modulus = M}) ->
    case bit_size(binary:encode_unsigned(M)) of
        N when N =< 1024 -> rsa1024;
        N when N =< 2048 -> rsa2048
    end;
algo_for_key({#'ECPoint'{}, {namedCurve, Curve}}) ->
    case Curve of
        prime256v1 -> eccp256;
        secp256r1 -> eccp256;
        {1,2,840,10045,3,1,7} -> eccp256;

        secp384r1 -> eccp384;
        {1,3,132,0,34} -> eccp384
    end.
