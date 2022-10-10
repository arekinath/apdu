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

-define(NIST_RID, 16#A0, 0, 0, 3, 8).
-define(PIV_PIX, 0, 0, 16#10, 0).
-define(PIV_AID, ?NIST_RID, ?PIV_PIX).

-define(INS_YK_SET_MGMT, 16#FF).
-define(INS_YK_IMPORT_ASYM, 16#FE).
-define(INS_YK_GET_VER, 16#FD).
-define(INS_YK_RESET, 16#FB).
-define(INS_YK_SET_PIN_RETRIES, 16#FA).
-define(INS_YK_GET_METADATA, 16#F7).
-define(INS_YK_GET_SERIAL, 16#F8).
-define(INS_YK_ATTEST, 16#F9).

-define(PIV_GET_DATA_INVTAGMAP, #{
    tag => 16#5C
}).

-define(PIV_APT_TAGMAP, #{
    16#61 => {apt, #{
        16#4F => aid,
        16#50 => app_label,
        16#79 => {alloc_auth, #{
            16#4F => aid
        }},
        16#5F50 => uri,
        16#AC => [{algos, #{
            16#80 => [algo],
            16#06 => oid
        }}]
    }},
    16#7F66 => unknown
}).

-define(PIV_APT_INVTAGMAP, #{
    apt => {16#61, [
        {aid, 16#4F},
        {alloc_auth, {16#79, #{
            aid => 16#4F
        }},
        {app_label, 16#50},
        {uri, 16#5F50},
        {algos, [{16#AC, [
            {algo, [16#80]},
            {oid, 16#06}
        ]}]}
    ]},
    unknown => 16#7F66
}).

-define(PIV_GEN_ASYM_INVTAGMAP, #{
    gen_asym => {16#AC, [
        {algo, 16#80},
        {params, {16#81, #{}}},
        {yk_pin_policy, 16#AA},
        {yk_touch_policy, 16#AB}
    ]}
}).

-define(PIV_GEN_ASYM_TAGMAP, #{
    16#7F49 => {asym_keypair, #{
        16#81 => modulus,
        16#82 => public_exp,
        16#86 => ec_point
    }}
}).

-define(PIV_GEN_AUTH_TAGMAP, #{
    16#7C => {general_auth, #{
        16#80 => witness,
        16#81 => challenge,
        16#82 => response,
        16#85 => exp
    }}
}).

-define(PIV_GEN_AUTH_INVTAGMAP, #{
    general_auth => {16#7C, [
        {witness, 16#80},
        {challenge, 16#81},
        {response, 16#82},
        {exp, 16#85}
    ]}
}).

-define(PIV_CHUID_TAGMAP, #{
    16#53 => {value, #{
        16#EE => buffer_len,
        16#30 => fascn,
        16#32 => org_id,
        16#33 => duns,
        16#34 => guid,
        16#35 => expiry,
        16#36 => chuuid,
        16#3E => signature,
        16#FE => lrc
    }}
}).

-define(PIV_CHUID_INVTAGMAP, #{
    16#53 => {value, [
        {buffer_len, 16#EE},
        {fascn, 16#30},
        {org_id, 16#32},
        {duns, 16#33},
        {guid, 16#34},
        {expiry, 16#35},
        {chuuid, 16#36},
        {signature, 16#3E},
        {lrc, 16#FE}
    ]}
}).

-define(PIV_DISCOV_TAGMAP, #{
    16#7E => {value, #{
        16#4F => aid,
        16#5F2F => pinpol
    }}
}).

-define(PIV_KEYHIST_TAGMAP, #{
    16#53 => {value, #{
        16#C1 => on_card_certs,
        16#C2 => off_card_certs,
        16#F3 => uri,
        16#FE => lrc
    }}
}).

-define(PIV_KEYHIST_INVTAGMAP, [
    {tag, 16#5C},
    {value, {16#53, [
        {on_card_certs, 16#C1},
        {off_card_certs, 16#C2},
        {uri, 16#F3},
        {lrc, 16#FE}
    ]}}
]).

-define(PIV_CERT_TAGMAP, #{
    16#5C => tag,
    16#53 => {value, #{
        16#70 => cert,
        16#71 => cert_info,
        16#72 => mscuid,
        16#FE => lrc
    }}
}).

-define(PIV_CERT_INVTAGMAP, [
    {tag, 16#5C},
    {value, {16#53, [
        {cert, 16#70},
        {cert_info, 16#71},
        {mscuid, 16#72},
        {lrc, 16#FE}
    ]}}
]).

-define(PIV_CARDCAP_TAGMAP, #{
    16#5C => tag,
    16#53 => {value, #{
        16#F0 => card_id,
        16#F1 => container_version,
        16#F2 => grammar_version,
        16#F3 => url,
        16#F4 => pkcs15,
        16#F5 => data_model,
        16#F6 => access_table,
        16#F7 => apdus,
        16#FA => redir_tag,
        16#FB => cap_tuples,
        16#FC => status_tuples,
        16#FD => next_ccc,
        16#E3 => ext_url,
        16#B4 => sec_obj,
        16#FE => lrc
    }}
}).

-define(PIV_CARDCAP_INVTAGMAP, [
    {tag, 16#5C},
    {value, {16#53, [
        {card_id, 16#F0},
        {container_version, 16#F1},
        {grammar_version, 16#F2},
        {url, 16#F3},
        {pkcs15, 16#F4},
        {data_model, 16#F5},
        {access_table, 16#F6},
        {apdus, 16#F7},
        {redir_tag, 16#FA},
        {cap_tuples, 16#FB},
        {status_tuples, 16#FC},
        {next_ccc, 16#FD},
        {ext_url, 16#E3},
        {sec_obj, 16#B4},
        {lrc, 16#FE}
    ]}}
]).

-define(PIV_PRINTINFO_TAGMAP, #{
    16#5C => tag,
    16#53 => {value, #{
        16#01 => name,
        16#02 => emp_affiliation,
        16#04 => expiry,
        16#05 => agency_serial,
        16#06 => issuer,
        16#07 => org_affiliation_1,
        16#08 => org_affiliation_2,
        16#FE => lrc,
        16#88 => {yubico, #{
            16#89 => admin_key
        }}
    }}
}).

-define(PIV_PRINTINFO_INVTAGMAP, [
    {tag, 16#5C},
    {value, {16#53, [
        {name, 16#01},
        {emp_affiliation, 16#02},
        {expiry, 16#04},
        {agency_serial, 16#05},
        {issuer, 16#06},
        {org_affiliation_1, 16#07},
        {org_affiliation_2, 16#08},
        {lrc, 16#FE},
        {yubico, {16#88, #{
            16#89 => admin_key
        }}}
    ]}}
]).

-define(YKPIV_MDATA_TAGMAP, #{
    16#01 => algo,
    16#02 => policy,
    16#03 => origin,
    16#04 => {public, #{
        16#81 => modulus,
        16#82 => public_exp,
        16#86 => ec_point
    }},
    16#05 => default,
    16#06 => retries
}).
