%%
%% Utilities for generating and parsing ISO7816 APDUs
%%
%% Copyright 2022, The University of Queensland
%% Author: Alex Wilson <alex@uq.edu.au>
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

%% @doc Utilities for parsing and generating ISO7816 APDUs. Also a
%%      apdu_transform implementation which does the same.
-module(iso7816).

-include("iso7816.hrl").

-ifdef(TEST).
-include_lib("eunit/include/eunit.hrl").
-endif.

-behaviour(apdu_transform).

% low-level encode/decode
-export([decode_apdu_cmd/1, decode_apdu_reply/1]).
-export([encode_apdu_cmd/1, encode_apdu_reply/1]).
-export([encode_ber_tlv/2, decode_ber_tlv/1]).
-export([encode_ber_tlvs/1, decode_ber_tlvs/1]).
-export([encode_ber_tlvs_map/2, decode_ber_tlvs_map/2]).
-export([invert_tlv_map/1]).
-export([decode_atr/1]).

-export([
    formats/0,
    init/1,
    begin_transaction/1,
    command/2,
    reply/2,
    end_transaction/1,
    terminate/1
]).

-export_type([
    atr_info/0,
    cls/0, ins/0, p1/0, p2/0, le/0, sw/0, tlv_map/0, tlv_inv_map/0
    ]).

-type channel() :: integer().

-type iso_ins() :: change_ref_data | external_auth | general_auth |
    generate_asym_key | get_response | get_data | put_data | select | verify |
    reset_retry_counter.

-type iso_sw() :: ok | {continue, integer()} | {requires_le, integer()} |
    {counter, integer()} |
    {warning, iso_warning_unch()} |
    {warning, iso_warning_ch()} |
    {error, {system, iso_error_unch()}} |
    {error, {system, iso_error_ch()}} |
    {error, {security, iso_error_sec()}} |
    {error, {denied, iso_error_cmd()}} |
    {error, {format, iso_error_format()}} |
    {error, {cla, iso_error_cla()}} |
    {error, {ins, not_supported}} |
    {error, {file, not_found}} |
    {error, {file, invalid}} |
    {error, {file, out_of_memory}} |
    {error, {file, exists}} |
    {error, {record, not_found}} |
    {error, {ref_data, not_found | unusable}} |
    {error, data_required} |
    {error, func_not_supported} |
    {error, p1p2} |
    {error, wrong_data} |
    {error, general_failure} |
    {desfire, integer()} |
    {error, integer()}.
-type iso_warning_unch() :: unchanged | part_corrupted | eof | deactivated |
    bad_format | terminated | no_input | {unchanged, integer()}.
-type iso_warning_ch() :: changed | bad_compare | file_full |
    {changed, integer()}.
-type iso_error_unch() :: unchanged | immediate_response | channel_share_denied |
    channel_denied | {unchanged, integer()}.
-type iso_error_ch() :: changed | memory_failure | {changed, integer()}.
-type iso_error_sec() :: integer().
-type iso_error_format() :: length | apdu | lc | lc_tlv_mismatch.
-type iso_error_cla() :: no_info | bad_chain | not_supported |
    {not_supported, channel | secure_msg | chain}.
-type iso_error_cmd() :: no_info | incompat_file | security_status |
    auth_method | conditions | no_ef | requires_secure_msg |
    bad_secure_msg | integer().

-type cls() :: iso | {iso, chain} | {iso, channel()} | {iso, chain, channel()} |
    integer().
%% The ISO7816 "class" field for a command APDU.

-type ins() :: iso_ins() | integer().
%% The ISO7816 "instruction" field for a command APDU.

-type p1() :: integer().
%% First parameter byte in a command APDU.

-type p2() :: integer().
%% Second parameter byte in a command APDU.

-type le() :: none | integer().
%% Expected length of reply field (optional).

-type sw() :: iso_sw() | integer().
%% Status word in a reply APDU.

-type atr_info() :: #{
    t0 => #{wi => integer()},
    t1 => #{ifsc => integer(), cwi => integer(), bwi => integer(),
        checksum => lrc | crc},
    status => {iso_sw(), LCS :: integer()},
    fi => integer(),
    fmax => integer(),
    di => integer(),
    guardn => integer(),
    historical_bytes => {proprietary, binary()} | standard,
    country_code => binary(),
    issuer => binary(),
    aid => binary(),
    initial_data_cmd => apdu:cmd(),
    initial_data => binary(),
    service_data => binary(),
    isseru_data => binary(),
    preissuing_data => binary(),
    df_selection => [full_name | part_name | path | file_id],
    implicit_df => boolean(),
    short_ef => boolean(),
    record_num => boolean(),
    record_id => boolean(),
    ef_ber_tlv => boolean(),
    write_functions => one_time | proprietary | write_or | write_and,
    long_private_tags => boolean(),
    data_unit_size => integer(),
    chain_support => boolean(),
    extended_length => boolean(),
    extended_length_atr => boolean(),
    logical_chan_assign => [card | host],
    logical_chans => integer(),
    application_family => binary(),
    leftovers => binary()
}. %%
%% Information decoded from an ATR value.

-type tlv_map() :: #{
    integer() =>
        atom() | {atom(), tlv_map() | [atom()] | [{atom(), tlv_map()}]}}.
%% A map used with <code>decode_ber_tlvs_map/2</code> to decode BER-TLV binary
%% data into structured maps.

-type tlv_inv_map() :: #{
    atom() =>
        integer() | {integer(), tlv_inv_map()} | [integer()] |
        [{integer(), tlv_inv_map()}]} |
    [ {atom(), integer() | {integer(), tlv_inv_map()} | [integer()] |
        [{integer(), tlv_inv_map()}]}].
%% The inverted form of a <code>tlv_map()</code>, used with
%% <code>encode_ber_tlvs_map/2</code>. Can be represented as a list instead
%% of a map (for order-sensitive uses).

-record(?MODULE, {
    proto :: pcsc:protocol(),
    state :: none | passthrough | apdu
}).

%% @private
formats() -> {[apdu, binary], binary}.

%% @private
init(Proto) -> {ok, #?MODULE{proto = Proto, state = none}}.

%% @private
begin_transaction(S = #?MODULE{}) -> {ok, S#?MODULE{state = none}}.

%% @private
end_transaction(S = #?MODULE{}) -> {ok, S}.

%% @private
command(Cmd = #apdu_cmd{proto = Proto0}, S = #?MODULE{state = none,
                                                      proto = DefProto}) ->
    Proto = case Proto0 of
        default -> DefProto;
        _ -> Proto0
    end,
    case (catch encode_apdu_cmd(Cmd)) of
        {'EXIT', Reason} ->
            {error, Reason};
        Bin when is_binary(Bin) ->
            {ok, [{Proto, Bin}], S#?MODULE{state = apdu}}
    end;
command(Cmd, S = #?MODULE{state = none}) ->
    {ok, [Cmd], S#?MODULE{state = passthrough}}.

%% @private
reply(R = {direct, _}, S = #?MODULE{state = apdu}) ->
    {ok, [R], S#?MODULE{state = none}};
reply({Proto, Data}, S = #?MODULE{state = apdu}) ->
    case (catch decode_apdu_reply(Data)) of
        {'EXIT', Reason} ->
            {error, Reason};
        Rec = #apdu_reply{} ->
            {ok, [Rec#apdu_reply{proto = Proto}], S#?MODULE{state = none}}
    end;
reply(R, S = #?MODULE{state = passthrough}) ->
    {ok, [R], S#?MODULE{state = none}}.

%% @private
terminate(_S) -> ok.

decode_cla(<<2#000:3, Chain:1, _SM:2, Channel:2>>) ->
    case Chain of
        0 ->
            case Channel of
                0 -> iso;
                _ -> {iso, Channel}
            end;
        1 ->
            case Channel of
                0 -> {iso, chain};
                _ -> {iso, chain, Channel}
            end
    end;
decode_cla(<<2#01:2, _SM:1, Chain:1, Channel:4>>) ->
    case Chain of
        0 ->
            case Channel of
                0 -> iso;
                _ -> {iso, Channel}
            end;
        1 ->
            case Channel of
                0 -> {iso, chain};
                _ -> {iso, chain, Channel}
            end
    end;
decode_cla(<<Value>>) -> Value.

encode_cla(iso) ->
    <<0>>;
encode_cla({iso, chain}) ->
    <<2#000:3, 1:1, 0:2, 0:2>>;
encode_cla({iso, Channel}) when (Channel > 3) ->
    <<2#01:2, 0:1, 0:1, Channel:4>>;
encode_cla({iso, Channel}) ->
    <<2#000:3, 0:1, 0:2, Channel:2>>;
encode_cla({iso, chain, Channel}) when (Channel > 3) ->
    <<2#01:2, 0:1, 1:1, Channel:4>>;
encode_cla({iso, chain, Channel}) ->
    <<2#000:3, 1:1, 0:2, Channel:2>>;
encode_cla(I) when is_integer(I) ->
    <<I>>.

decode_ins(Cla, Ins) when (Cla =:= iso) or (Cla =:= {iso, chain}) ->
    case Ins of
        16#20 -> verify;
        16#24 -> change_ref_data;
        16#46 -> generate_asym_key;
        16#47 -> generate_asym_key;
        16#86 -> general_auth;
        16#87 -> general_auth;
        16#a4 -> select;
        16#c0 -> get_response;
        16#cb -> get_data;
        16#cd -> get_data;
        16#2c -> reset_retry_counter;
        16#2d -> reset_retry_counter;
        16#db -> put_data;
        16#da -> put_data;
        _ -> Ins
    end;
decode_ins(_Cla, Ins) -> Ins.

encode_ins(verify) -> 16#20;
encode_ins(change_ref_data) -> 16#24;
encode_ins(generate_asym_key) -> 16#47;
encode_ins(general_auth) -> 16#87;
encode_ins(select) -> 16#a4;
encode_ins(get_response) -> 16#c0;
encode_ins(get_data) -> 16#cb;
encode_ins(reset_retry_counter) -> 16#2c;
encode_ins(put_data) -> 16#db;
encode_ins(I) when is_integer(I) -> I;
encode_ins(Ins) -> error({invalid_ins, Ins}).

-spec decode_apdu_cmd(binary()) -> apdu:cmd().
decode_apdu_cmd(<<ClaBin:1/binary, Ins, P1, P2>>) ->
    Cla = decode_cla(ClaBin),
    #apdu_cmd{
        cla = Cla,
        ins = decode_ins(Cla, Ins),
        p1 = P1,
        p2 = P2
    };
decode_apdu_cmd(<<ClaBin:1/binary, Ins, P1, P2, Le>>) ->
    Cla = decode_cla(ClaBin),
    #apdu_cmd{
        cla = Cla,
        ins = decode_ins(Cla, Ins),
        p1 = P1,
        p2 = P2,
        le = Le
    };
decode_apdu_cmd(<<ClaBin:1/binary, Ins, P1, P2, Lc, Data:Lc/binary>>) ->
    Cla = decode_cla(ClaBin),
    #apdu_cmd{
        cla = Cla,
        ins = decode_ins(Cla, Ins),
        p1 = P1,
        p2 = P2,
        data = Data
    };
decode_apdu_cmd(<<ClaBin:1/binary, Ins, P1, P2, Lc, Data:Lc/binary, Le>>) ->
    Cla = decode_cla(ClaBin),
    #apdu_cmd{
        cla = Cla,
        ins = decode_ins(Cla, Ins),
        p1 = P1,
        p2 = P2,
        data = Data,
        le = Le
    };
decode_apdu_cmd(_) -> {error, bad_format}.

-spec encode_apdu_cmd(apdu:cmd()) -> binary().
encode_apdu_cmd(#apdu_cmd{cla = Cla, ins = Ins, p1 = P1, p2 = P2,
                          data = none, le = none}) ->
    ClaBin = encode_cla(Cla),
    InsInt = encode_ins(Ins),
    <<ClaBin/binary, InsInt, P1, P2>>;
encode_apdu_cmd(#apdu_cmd{cla = Cla, ins = Ins, p1 = P1, p2 = P2,
                          data = none, le = Le}) ->
    ClaBin = encode_cla(Cla),
    InsInt = encode_ins(Ins),
    <<ClaBin/binary, InsInt, P1, P2, Le>>;
encode_apdu_cmd(#apdu_cmd{cla = Cla, ins = Ins, p1 = P1, p2 = P2,
                          data = Data, le = none}) ->
    ClaBin = encode_cla(Cla),
    InsInt = encode_ins(Ins),
    <<ClaBin/binary, InsInt, P1, P2, (byte_size(Data)):8, Data/binary>>;
encode_apdu_cmd(#apdu_cmd{cla = Cla, ins = Ins, p1 = P1, p2 = P2,
                          data = Data, le = Le}) ->
    ClaBin = encode_cla(Cla),
    InsInt = encode_ins(Ins),
    <<ClaBin/binary, InsInt, P1, P2, (byte_size(Data)):8, Data/binary, Le>>;
encode_apdu_cmd(_) -> error(bad_format).

decode_sw(<<16#90, _>>) -> ok;
decode_sw(<<16#61, Rem>>) -> {continue, Rem};
decode_sw(<<16#6c, Le>>) -> {requires_le, Le};

decode_sw(<<16#91, N>>) -> {desfire, N};

decode_sw(<<16#62, 16#00>>) -> {warning, unchanged};
decode_sw(<<16#62, 16#81>>) -> {warning, part_corrupted};
decode_sw(<<16#62, 16#82>>) -> {warning, eof};
decode_sw(<<16#62, 16#83>>) -> {warning, deactivated};
decode_sw(<<16#62, 16#84>>) -> {warning, bad_format};
decode_sw(<<16#62, 16#85>>) -> {warning, terminated};
decode_sw(<<16#62, 16#86>>) -> {warning, no_input};
decode_sw(<<16#62, 16#87>>) -> {warning, deactivated};
decode_sw(<<16#62, I>>) -> {warning, {unchanged, I}};

decode_sw(<<16#63, 16#00>>) -> {warning, changed};
decode_sw(<<16#63, 16#40>>) -> {warning, bad_compare};
decode_sw(<<16#63, 16#81>>) -> {warning, file_full};
decode_sw(<<16#63, 16#C:4, Count:4>>) -> {counter, Count};
decode_sw(<<16#63, I>>) -> {warning, {changed, I}};

decode_sw(<<16#64, 16#00>>) -> {error, {system, unchanged}};
decode_sw(<<16#64, 16#01>>) -> {error, {system, immediate_response}};
decode_sw(<<16#64, 16#81>>) -> {error, {system, channel_share_denied}};
decode_sw(<<16#64, 16#82>>) -> {error, {system, channel_denied}};
decode_sw(<<16#64, I>>) -> {error, {system, {unchanged, I}}};

decode_sw(<<16#65, 16#00>>) -> {error, {system, changed}};
decode_sw(<<16#65, 16#81>>) -> {error, {system, memory_failure}};
decode_sw(<<16#65, I>>) -> {error, {system, {changed, I}}};

decode_sw(<<16#66, I>>) -> {error, {security, I}};

decode_sw(<<16#67, 16#00>>) -> {error, {format, length}};
decode_sw(<<16#67, 16#01>>) -> {error, {format, apdu}};
decode_sw(<<16#67, 16#02>>) -> {error, {format, lc}};
decode_sw(<<16#67, I>>) -> {error, {format, I}};

decode_sw(<<16#68, 16#00>>) -> {error, {cla, no_info}};
decode_sw(<<16#68, 16#81>>) -> {error, {cla, {not_supported, channel}}};
decode_sw(<<16#68, 16#82>>) -> {error, {cla, {not_supported, secure_msg}}};
decode_sw(<<16#68, 16#83>>) -> {error, {cla, bad_chain}};
decode_sw(<<16#68, 16#84>>) -> {error, {cla, {not_supported, chain}}};
decode_sw(<<16#68, I>>) -> {error, {cla, I}};

decode_sw(<<16#69, 16#00>>) -> {error, {denied, no_info}};
decode_sw(<<16#69, 16#81>>) -> {error, {denied, incompat_file}};
decode_sw(<<16#69, 16#82>>) -> {error, {denied, security_status}};
% in 7816-4 this is listed as "Authentication method blocked", but Javacard
% and other specs call it SW_FILE_INVALID
decode_sw(<<16#69, 16#83>>) -> {error, {file, invalid}};
decode_sw(<<16#69, 16#84>>) -> {error, {ref_data, unusable}};
decode_sw(<<16#69, 16#85>>) -> {error, {denied, conditions}};
decode_sw(<<16#69, 16#86>>) -> {error, {denied, no_ef}};
decode_sw(<<16#69, 16#87>>) -> {error, {denied, requires_secure_msg}};
decode_sw(<<16#69, 16#88>>) -> {error, {denied, bad_secure_msg}};
decode_sw(<<16#69, I>>) -> {error, {denied, I}};

decode_sw(<<16#6A, 16#00>>) -> {error, p1p2};
decode_sw(<<16#6A, 16#80>>) -> {error, wrong_data};
decode_sw(<<16#6A, 16#81>>) -> {error, func_not_supported};
decode_sw(<<16#6A, 16#82>>) -> {error, {file, not_found}};
decode_sw(<<16#6A, 16#83>>) -> {error, {record, not_found}};
decode_sw(<<16#6A, 16#84>>) -> {error, {file, out_of_memory}};
decode_sw(<<16#6A, 16#85>>) -> {error, {format, lc_tlv_mismatch}};
decode_sw(<<16#6A, 16#86>>) -> {error, p1p2};
decode_sw(<<16#6A, 16#87>>) -> {error, data_required};
decode_sw(<<16#6A, 16#88>>) -> {error, {ref_data, not_found}};
decode_sw(<<16#6A, 16#89>>) -> {error, {file, exists}};
decode_sw(<<16#6A, 16#8A>>) -> {error, {file, exists}};

decode_sw(<<16#6D, 16#00>>) -> {error, {ins, not_supported}};

decode_sw(<<16#6E, 16#00>>) -> {error, {cla, not_supported}};

decode_sw(<<16#6F, 16#00>>) -> {error, general_failure};

decode_sw(<<I:16/big>>) -> {error, I}.

encode_sw(ok) -> <<16#90, 0>>;
encode_sw({continue, Rem}) -> <<16#61, Rem>>;
encode_sw({requires_le, Le}) -> <<16#6c, Le>>;

encode_sw({desfire, N}) -> <<16#91, N>>;

encode_sw({warning, unchanged}) -> <<16#62, 16#00>>;
encode_sw({warning, part_corrupted}) -> <<16#62, 16#81>>;
encode_sw({warning, eof}) -> <<16#62, 16#82>>;
encode_sw({warning, deactivated}) -> <<16#62, 16#83>>;
encode_sw({warning, bad_format}) -> <<16#62, 16#84>>;
encode_sw({warning, terminated}) -> <<16#62, 16#85>>;
encode_sw({warning, no_input}) -> <<16#62, 16#86>>;
encode_sw({warning, {unchanged, I}}) when is_integer(I) -> <<16#62, I>>;

encode_sw({warning, changed}) -> <<16#63, 16#00>>;
encode_sw({warning, bad_compare}) -> <<16#63, 16#40>>;
encode_sw({warning, file_full}) -> <<16#63, 16#81>>;
encode_sw({counter, Count}) -> <<16#63, 16#C:4, Count:4>>;
encode_sw({warning, {changed, I}}) when is_integer(I) -> <<16#63, I>>;

encode_sw({error, {system, unchanged}}) -> <<16#64, 16#00>>;
encode_sw({error, {system, immediate_response}}) -> <<16#64, 16#01>>;
encode_sw({error, {system, channel_share_denied}}) -> <<16#64, 16#81>>;
encode_sw({error, {system, channel_denied}}) -> <<16#64, 16#82>>;
encode_sw({error, {system, {unchanged, I}}}) when is_integer(I) -> <<16#64, I>>;

encode_sw({error, {system, changed}}) -> <<16#65, 16#00>>;
encode_sw({error, {system, memory_failure}}) -> <<16#65, 16#81>>;
encode_sw({error, {system, {changed, I}}}) when is_integer(I) -> <<16#65, I>>;

encode_sw({error, {security, I}}) when is_integer(I) -> <<16#66, I>>;

encode_sw({error, {format, length}}) -> <<16#67, 16#00>>;
encode_sw({error, {format, apdu}}) -> <<16#67, 16#01>>;
encode_sw({error, {format, lc}}) -> <<16#67, 16#02>>;
encode_sw({error, {format, I}}) when is_integer(I) -> <<16#67, I>>;

encode_sw({error, {cla, no_info}}) -> <<16#68, 16#00>>;
encode_sw({error, {cla, {not_supported, channel}}}) -> <<16#68, 16#81>>;
encode_sw({error, {cla, {not_supported, secure_msg}}}) -> <<16#68, 16#82>>;
encode_sw({error, {cla, bad_chain}}) -> <<16#68, 16#83>>;
encode_sw({error, {cla, {not_supported, chain}}}) -> <<16#68, 16#84>>;
encode_sw({error, {cla, I}}) when is_integer(I) -> <<16#68, I>>;

encode_sw({error, {denied, no_info}}) -> <<16#69, 16#00>>;
encode_sw({error, {denied, incompat_file}}) -> <<16#69, 16#81>>;
encode_sw({error, {denied, security_status}}) -> <<16#69, 16#82>>;
% in 7816-4 this is listed as "Authentication method blocked", but Javacard
% and other specs call it SW_FILE_INVALID
encode_sw({error, {file, invalid}}) -> <<16#69, 16#83>>;
encode_sw({error, {ref_data, unusable}}) -> <<16#69, 16#84>>;
encode_sw({error, {denied, conditions}}) -> <<16#69, 16#85>>;
encode_sw({error, {denied, no_ef}}) -> <<16#69, 16#86>>;
encode_sw({error, {denied, requires_secure_msg}}) -> <<16#69, 16#87>>;
encode_sw({error, {denied, bad_secure_msg}}) -> <<16#69, 16#88>>;
encode_sw({error, {denied, I}}) when is_integer(I) -> <<16#69, I>>;

encode_sw({error, wrong_data}) -> <<16#6A, 16#80>>;
encode_sw({error, func_not_supported}) -> <<16#6A, 16#81>>;
encode_sw({error, {file, not_found}}) -> <<16#6A, 16#82>>;
encode_sw({error, {record, not_found}}) -> <<16#6A, 16#83>>;
encode_sw({error, {file, out_of_memory}}) -> <<16#6A, 16#84>>;
encode_sw({error, {format, lc_tlv_mismatch}}) -> <<16#6A, 16#85>>;
encode_sw({error, p1p2}) -> <<16#6A, 16#86>>;
encode_sw({error, data_required}) -> <<16#6A, 16#87>>;
encode_sw({error, {ref_data, not_found}}) -> <<16#6A, 16#88>>;
encode_sw({error, {file, exists}}) -> <<16#6A, 16#89>>;

encode_sw({error, {ins, not_supported}}) -> <<16#6D, 16#00>>;

encode_sw({error, {cla, not_supported}}) -> <<16#6E, 16#00>>;

encode_sw({error, general_failure}) -> <<16#6F, 16#00>>;

encode_sw({error, I}) when is_integer(I) -> <<I:16/big>>;

encode_sw(SW) -> error({invalid_sw, SW}).

-spec decode_apdu_reply(binary()) -> apdu:reply().
decode_apdu_reply(<<SW:2/binary>>) ->
    #apdu_reply{sw = decode_sw(SW)};
decode_apdu_reply(Bin) ->
    <<Data:(byte_size(Bin) - 2)/binary, SW:2/binary>> = Bin,
    #apdu_reply{sw = decode_sw(SW), data = Data}.

-spec encode_apdu_reply(apdu:reply()) -> binary().
encode_apdu_reply(#apdu_reply{data = none, sw = SW}) ->
    encode_sw(SW);
encode_apdu_reply(#apdu_reply{data = Data, sw = SW}) ->
    <<Data/binary, (encode_sw(SW))/binary>>;
encode_apdu_reply(_) -> error(bad_record).

-spec encode_ber_len_data(binary()) -> binary().
encode_ber_len_data(Data) ->
    Len = byte_size(Data),
    if
        (Len < (1 bsl 7)) -> <<Len, Data/binary>>;
        (Len < (1 bsl 8)) -> <<16#81, Len, Data/binary>>;
        (Len < (1 bsl 16)) -> <<16#82, Len:16/big, Data/binary>>
    end.

-spec encode_ber_tlv(integer(), binary()) -> binary().
encode_ber_tlv(Tag, Data) ->
    if
        (Tag > 16#ff) -> <<Tag:16/big, (encode_ber_len_data(Data))/binary>>;
        true -> <<Tag:8, (encode_ber_len_data(Data))/binary>>
    end.

-type ber_tlv_tag() :: {Tag :: integer(), Data :: binary() | [ber_tlv_tag()]}.
-spec encode_ber_tlvs([ber_tlv_tag()]) -> binary().
encode_ber_tlvs(Tlvs) ->
    iolist_to_binary(lists:map(fun
        ({T, D}) when is_binary(D) -> encode_ber_tlv(T, D);
        ({T, D}) when is_list(D) -> encode_ber_tlv(T, encode_ber_tlvs(D))
    end, Tlvs)).

-spec take_next_until_high_bit(binary(), binary()) -> {binary(), binary()}.
take_next_until_high_bit(SoFar, <<0:1, N:7, Rem/binary>>) ->
    {<<SoFar/binary, 0:1,N:7>>, Rem};
take_next_until_high_bit(SoFar, <<1:1, N:7, Rem/binary>>) ->
    SoFar1 = <<SoFar/binary, 0:1,N:7>>,
    take_next_until_high_bit(SoFar1, Rem).

-spec decode_ber_len_data(binary()) -> {ok, binary(), binary()} | {error, term()}.
decode_ber_len_data(<<16#82, Len:16/big, Data:(Len)/binary, Rest/binary>>) ->
    {ok, Data, Rest};
decode_ber_len_data(<<16#81, Len:8, Data:(Len)/binary, Rest/binary>>) ->
    {ok, Data, Rest};
decode_ber_len_data(<<0:1, Len:7, Data:(Len)/binary, Rest/binary>>) ->
    {ok, Data, Rest};
decode_ber_len_data(_) -> {error, bad_tag_length}.

-spec decode_ber_tlv(binary()) -> {ok, integer(), binary(), binary()} | {error, term()}.
decode_ber_tlv(<<TopBits:3, 2#11111:5, Rem/binary>>) ->
    case (catch take_next_until_high_bit(<<>>, Rem)) of
        {'EXIT', _Reason} ->
            {error, invalid_or_incomplete_tag};
        {TagBin, Rem1} ->
            Tag = binary:decode_unsigned(
                <<TopBits:3, 2#11111:5, TagBin/binary>>),
            case decode_ber_len_data(Rem1) of
                {ok, Data, Rem2} -> {ok, Tag, Data, Rem2};
                Err -> Err
            end
    end;
decode_ber_tlv(<<Tag, Rem/binary>>) ->
    case decode_ber_len_data(Rem) of
        {ok, Data, Rem1} -> {ok, Tag, Data, Rem1};
        Err -> Err
    end;
decode_ber_tlv(_) ->
    {error, no_tag}.

-spec decode_ber_tlvs(binary()) -> {ok, [ber_tlv_tag()]} | {error, term()}.
decode_ber_tlvs(Bin) ->
    case decode_ber_tlvs([], Bin) of
        {ok, Tlvs} -> {ok, lists:reverse(Tlvs)};
        Err -> Err
    end.
decode_ber_tlvs(SoFar, Bin) ->
    case decode_ber_tlv(Bin) of
        {ok, Tag, Data, <<>>} -> {ok, [{Tag, Data} | SoFar]};
        {ok, Tag, Data, Rem} -> decode_ber_tlvs([{Tag, Data} | SoFar], Rem);
        Err -> Err
    end.

%% @doc Converts a <code>tlv_map()</code> into a <code>tlv_inv_map()</code>.
-spec invert_tlv_map(tlv_map()) -> tlv_inv_map().
invert_tlv_map(Map) ->
    maps:fold(fun (K, V, Acc) ->
        case V of
            [{A, SubMap}] -> Acc#{A => [{K, invert_tlv_map(SubMap)}]};
            {A, SubMap} -> Acc#{A => {K, invert_tlv_map(SubMap)}};
            [A] -> Acc#{A => [K]};
            A -> Acc#{A => K}
        end
    end, #{}, Map).

%% @doc Decodes BER-TLV data into structured maps using a provided schema.
%%
%% An example schema (for the NIST PIV APT):
%%
%% <pre>
%%  #{
%%    16#61 => {apt, #{
%%      16#4F => aid,
%%      16#50 => app_label,
%%      16#79 => {alloc_auth, #{
%%        16#4F => aid
%%      }},
%%      16#5F50 => uri,
%%      16#AC => {algos, #{
%%        16#80 => [algo],
%%        16#06 => oid
%%      }}
%%    }}
%%  }
%% </pre>
%%
%% Will produce maps like the following:
%%
%% <pre>
%%    #{
%%        apt => #{
%%            aid => &lt;&lt;1,2,3,4>>,
%%            app_label => &lt;&lt;"Testing">>,
%%            uri => &lt;&lt;"https://test.com">>,
%%            algos => #{
%%                algo => [&lt;&lt;1>>, &lt;&lt;2>>, &lt;&lt;3>>]
%%            }
%%        }
%%    }
%% </pre>
-spec decode_ber_tlvs_map(binary(), tlv_map()) -> {ok, map()}.
decode_ber_tlvs_map(Bin, Map) ->
    decode_ber_tlvs_map(#{}, Bin, Map).
decode_ber_tlvs_map(SoFar, Bin, Map) ->
    case decode_ber_tlv(Bin) of
        {ok, Tag, Data, Rem} ->
            VRet = case Map of
                #{Tag := [{Atom, SubMap}]} ->
                    case decode_ber_tlvs_map(Data, SubMap) of
                        {ok, V} ->
                            case SoFar of
                                #{Atom := Vs0} ->
                                    {ok, SoFar#{Atom => Vs0 ++ [V]}};
                                _ ->
                                    {ok, SoFar#{Atom => [V]}}
                            end;
                        Err ->
                            Err
                    end;
                #{Tag := {Atom, SubMap}} ->
                    case decode_ber_tlvs_map(Data, SubMap) of
                        {ok, V} ->
                            {ok, SoFar#{Atom => V}};
                        Err ->
                            Err
                    end;
                #{Tag := [Atom]} ->
                    case SoFar of
                        #{Atom := Vs0} ->
                            {ok, SoFar#{Atom => Vs0 ++ [Data]}};
                        _ ->
                            {ok, SoFar#{Atom => [Data]}}
                    end;
                #{Tag := Atom} ->
                    {ok, SoFar#{Atom => Data}};
                _ ->
                    {error, {unmapped_tag, Tag}}
            end,
            case {Rem, VRet} of
                {<<>>, _} ->
                    VRet;
                {_, {ok, SoFar1}} ->
                    decode_ber_tlvs_map(SoFar1, Rem, Map);
                {_, _} ->
                    VRet
            end;
        Err -> Err
    end.

%% @doc Encodes structured maps into BER-TLV data using a provided schema.
-spec encode_ber_tlvs_map(map(), tlv_inv_map()) -> binary().
encode_ber_tlvs_map(Map, InvTagMap) when is_map(InvTagMap) ->
    Iter = maps:iterator(Map),
    iolist_to_binary(lists:reverse(
        encode_ber_tlvs_map([], Iter, InvTagMap)));
encode_ber_tlvs_map(Map, InvTagMap) when is_list(InvTagMap) ->
    iolist_to_binary(lists:reverse(
        encode_ber_tlvs_map_list([], Map, InvTagMap))).

encode_ber_tlvs_map_list(SoFar, Map, []) ->
    case maps:keys(Map) of
        [K | _] -> error({unmapped_tag, K});
        [] -> SoFar
    end;
encode_ber_tlvs_map_list(SoFar, Map, [{Atom, Spec} | Rest]) ->
    case Map of
        #{Atom := V} ->
            Map1 = maps:remove(Atom, Map),
            case Spec of
                [{Tag, SubTagMap}] when is_integer(Tag) ->
                    SoFar1 = lists:foldl(fun (VV, Acc) ->
                        VV1 = encode_ber_tlvs_map(VV, SubTagMap),
                        [encode_ber_tlv(Tag, VV1) | Acc]
                    end, SoFar, V),
                    encode_ber_tlvs_map_list(SoFar1, Map1, Rest);
                {Tag, SubTagMap} when is_integer(Tag) ->
                    V1 = encode_ber_tlvs_map(V, SubTagMap),
                    SoFar1 = [encode_ber_tlv(Tag, V1) | SoFar],
                    encode_ber_tlvs_map_list(SoFar1, Map1, Rest);
                [Tag] when is_integer(Tag) ->
                    SoFar1 = lists:foldl(fun (VV, Acc) ->
                        [encode_ber_tlv(Tag, VV) | Acc]
                    end, SoFar, V),
                    encode_ber_tlvs_map_list(SoFar1, Map1, Rest);
                Tag when is_integer(Tag) ->
                    SoFar1 = [encode_ber_tlv(Tag, V) | SoFar],
                    encode_ber_tlvs_map_list(SoFar1, Map1, Rest)
            end;
        _ ->
            encode_ber_tlvs_map_list(SoFar, Map, Rest)
    end.

encode_ber_tlvs_map(SoFar, Iter, InvTagMap) ->
    case maps:next(Iter) of
        none ->
            SoFar;
        {Atom, V, Iter1} ->
            case InvTagMap of
                #{Atom := [{Tag, SubTagMap}]} ->
                    SoFar1 = lists:foldl(fun (VV, Acc) ->
                        VV1 = encode_ber_tlvs_map(VV, SubTagMap),
                        [encode_ber_tlv(Tag, VV1) | Acc]
                    end, SoFar, V),
                    encode_ber_tlvs_map(SoFar1, Iter1, InvTagMap);
                #{Atom := {Tag, SubTagMap}} ->
                    V1 = encode_ber_tlvs_map(V, SubTagMap),
                    SoFar1 = [encode_ber_tlv(Tag, V1) | SoFar],
                    encode_ber_tlvs_map(SoFar1, Iter1, InvTagMap);
                #{Atom := [Tag]} ->
                    SoFar1 = lists:foldl(fun (VV, Acc) ->
                        [encode_ber_tlv(Tag, VV) | Acc]
                    end, SoFar, V),
                    encode_ber_tlvs_map(SoFar1, Iter1, InvTagMap);
                #{Atom := Tag} ->
                    SoFar1 = [encode_ber_tlv(Tag, V) | SoFar],
                    encode_ber_tlvs_map(SoFar1, Iter1, InvTagMap);
                _ ->
                    error({unmapped_tag, Atom})
            end
    end.

-define(ATR_Y, HasTD:1, HasTC:1, HasTB:1, HasTA:1).

maybe_take_byte(0, Rest) -> {none, Rest};
maybe_take_byte(1, <<B, Rest/binary>>) -> {<<B>>, Rest}.

decode_next_intf(Intfs0, <<?ATR_Y, T:4, Rest0/binary>>) ->
    {TA, Rest1} = maybe_take_byte(HasTA, Rest0),
    {TB, Rest2} = maybe_take_byte(HasTB, Rest1),
    {TC, Rest3} = maybe_take_byte(HasTC, Rest2),
    Intfs1 = case T of
        0 ->
            WI = case TC of
                none -> 10;
                <<V>> -> V
            end,
            Intfs0#{t0 => #{wi => WI}};
        1 ->
            IFSC = case TA of
                none -> 32;
                <<V>> -> V
            end,
            {BWI, CWI} = case TB of
                none -> {4, 13};
                <<B:4, C:4>> -> {B, C}
            end,
            Checksum = case TC of
                <<_:7, 1:1>> -> crc;
                _ -> lrc
            end,
            Intfs0#{t1 => #{ifsc => IFSC, cwi => CWI, bwi => BWI,
                checksum => Checksum}};
        15 ->
            ModeChange = case TA of
                none -> unable;
                <<0:1, _:7>> -> capable;
                <<1:1, _:7>> -> unable
            end,
            Intfs0#{mode_change => ModeChange}
    end,
    case HasTD of
        1 ->
            decode_next_intf(Intfs1, Rest3);
        0 ->
            {Intfs1, Rest3}
    end.

-define(SFT1, DFByFullName:1, DFByPartName:1, DFByPath:1, DFByFileID:1,
    ImplicitDF:1, ShortEF:1, RecordNum:1, RecordID:1).
-define(SFT2, EFBerTlv:1, WriteFunc:2, FFValid:1, DataUnitSize:4).
-define(SFT3, Chain:1, ExtLen:1, ExtLenATR:1, LogiChanCard:1, LogiChanHost:1,
    LCY:1, LCZ:1, LCT:1).

bit_boolean(1) -> true;
bit_boolean(0) -> false.

decode_compact_tlv(Intfs0, <<>>) -> Intfs0;
decode_compact_tlv(Intfs0,
        <<16#1:4, Len:4, CountryCode:Len/binary, Rest/binary>>) ->
    Intfs1 = Intfs0#{country_code => CountryCode},
    decode_compact_tlv(Intfs1, Rest);
decode_compact_tlv(Intfs0,
        <<16#2:4, Len:4, Issuer:Len/binary, Rest/binary>>) ->
    Intfs1 = Intfs0#{issuer => Issuer},
    decode_compact_tlv(Intfs1, Rest);
decode_compact_tlv(Intfs0,
        <<16#F:4, Len:4, AID:Len/binary, Rest/binary>>) ->
    Intfs1 = Intfs0#{aid => AID},
    decode_compact_tlv(Intfs1, Rest);
decode_compact_tlv(Intfs0,
        <<16#4F, Len:8, AID:Len/binary, Rest/binary>>) ->
    Intfs1 = Intfs0#{aid => AID},
    decode_compact_tlv(Intfs1, Rest);
decode_compact_tlv(Intfs0,
        <<16#4:4, Len:4, InitialData:Len/binary, Rest/binary>>) ->
    Intfs1 = case InitialData of
        <<IDataLen>> ->
            Intfs0#{initial_data_cmd =>
                #apdu_cmd{ins = read_binary, le = IDataLen}};
        <<1:1, P1:7, IDataLen>> ->
            Intfs0#{initial_data_cmd =>
                #apdu_cmd{ins = read_binary, p1 = P1, le = IDataLen}};
        <<0:1, _:3, P2High:4, IDataLen>> ->
            <<P2:8>> = <<P2High:4, 2#110:4>>,
            Intfs0#{initial_data_cmd =>
                #apdu_cmd{ins = read_record, p1 = 1, p2 = P2, le = IDataLen}};
        B when byte_size(B) =:= 16#F ->
            Intfs0#{aid => B};
        B ->
            Intfs0#{initial_data => B}
    end,
    decode_compact_tlv(Intfs1, Rest);
decode_compact_tlv(Intfs0,
        <<16#3:4, Len:4, D:Len/binary, Rest/binary>>) ->
    Intfs1 = Intfs0#{service_data => D},
    decode_compact_tlv(Intfs1, Rest);
decode_compact_tlv(Intfs0,
        <<16#5:4, Len:4, D:Len/binary, Rest/binary>>) ->
    Intfs1 = Intfs0#{issuer_data => D},
    decode_compact_tlv(Intfs1, Rest);
decode_compact_tlv(Intfs0,
        <<16#6:4, Len:4, D:Len/binary, Rest/binary>>) ->
    Intfs1 = Intfs0#{preissuing_data => D},
    decode_compact_tlv(Intfs1, Rest);
decode_compact_tlv(Intfs0,
        <<16#7:4, Len:4, D:Len/binary, Rest/binary>>) ->
    Intfs1 = case D of
        <<?SFT1, RemSFT0/binary>> ->
            DFSels0 = case DFByFullName of
                1 -> [full_name]; 0 -> [] end,
            DFSels1 = case DFByPartName of
                1 -> [part_name | DFSels0]; 0 -> DFSels0 end,
            DFSels2 = case DFByPath of
                1 -> [path | DFSels1]; 0 -> DFSels1 end,
            DFSels3 = case DFByFileID of
                1 -> [file_id | DFSels2]; 0 -> DFSels2 end,
            Intfs0#{
                df_selection => DFSels3,
                implicit_df => bit_boolean(ImplicitDF),
                short_ef => bit_boolean(ShortEF),
                record_num => bit_boolean(RecordNum),
                record_id => bit_boolean(RecordID)
            };
        <<>> -> RemSFT0 = <<>>, Intfs0
    end,
    Intfs2 = case RemSFT0 of
        <<?SFT2, RemSFT1/binary>> ->
            WriteFuncAtom = case WriteFunc of
                2#00 -> one_time;
                2#01 -> proprietary;
                2#10 -> write_or;
                2#11 -> write_and
            end,
            Intfs1#{
                ef_ber_tlv => bit_boolean(EFBerTlv),
                write_functions => WriteFuncAtom,
                long_private_tags => bit_boolean(FFValid),
                data_unit_size => 1 bsl DataUnitSize
            };
        <<>> -> RemSFT1 = <<>>, Intfs1
    end,
    Intfs3 = case RemSFT1 of
        <<?SFT3>> ->
            LogiChanAssign0 = case LogiChanCard of
                1 -> [card]; 0 -> [] end,
            LogiChanAssign1 = case LogiChanHost of
                1 -> [host | LogiChanAssign0]; 0 -> LogiChanAssign0 end,
            LogiChanNum = case {LCY, LCZ, LCT} of
                {1, 1, 1} -> 8;
                {_, _, _} -> 4*LCY + 2*LCZ + LCT + 1
            end,
            Intfs2#{
                chain_support => bit_boolean(Chain),
                extended_length => bit_boolean(ExtLen),
                extended_length_atr => bit_boolean(ExtLenATR),
                logical_chan_assign => LogiChanAssign1,
                logical_chans => LogiChanNum
            };
        <<>> -> Intfs2
    end,
    decode_compact_tlv(Intfs3, Rest);
decode_compact_tlv(Intfs0,
        <<16#9:4, Len:4, D:Len/binary, Rest/binary>>) ->
    Intfs1 = Intfs0#{application_family => D},
    decode_compact_tlv(Intfs1, Rest);
decode_compact_tlv(Intfs0,
        <<16#8:4, Len:4, D:Len/binary, Rest/binary>>) ->
    Intfs1 = Intfs0#{status => decode_status(D)},
    decode_compact_tlv(Intfs1, Rest);
decode_compact_tlv(Intfs0,
        <<Tag:4, Len:4, D:Len/binary, Rest/binary>>) ->
    Intfs1 = Intfs0#{Tag => D},
    decode_compact_tlv(Intfs1, Rest);
decode_compact_tlv(Intfs0, Other) ->
    Intfs0#{leftovers => Other}.

decode_status(<<LCS>>) -> {ok, LCS};
decode_status(<<SW:2/binary>>) -> decode_sw(SW);
decode_status(<<LCS, SW:2/binary>>) -> {decode_sw(SW), LCS}.

decode_hist_bytes(Intfs0, <<16#00, Rest0/binary>>) ->
    StatusInd = binary:part(Rest0, {byte_size(Rest0), -3}),
    Rest1 = binary:part(Rest0, {0, byte_size(Rest0) - 3}),
    Intfs1 = Intfs0#{historical_bytes => standard,
        status => decode_status(StatusInd)},
    decode_compact_tlv(Intfs1, Rest1);
decode_hist_bytes(Intfs0, <<16#80, Rest/binary>>) ->
    decode_compact_tlv(Intfs0#{historical_bytes => standard}, Rest);
decode_hist_bytes(Intfs0, Other) ->
    Intfs0#{historical_bytes => {proprietary, Other}}.

%% @doc Decodes an ATR into the different encoded fields and information.
-spec decode_atr(binary()) -> atr_info().
decode_atr(<<16#3B, ?ATR_Y, K:4, Rest0/binary>>) ->
    {TA1, Rest1} = maybe_take_byte(HasTA, Rest0),
    {_TB1, Rest2} = maybe_take_byte(HasTB, Rest1),
    {TC1, Rest3} = maybe_take_byte(HasTC, Rest2),
    {Fi, Fmax} = case TA1 of
        none -> {372, 5};
        <<2#0000:4, _:4>> -> {372, 4};
        <<2#0001:4, _:4>> -> {372, 5};
        <<2#0010:4, _:4>> -> {558, 6};
        <<2#0011:4, _:4>> -> {744, 8};
        <<2#0100:4, _:4>> -> {1116, 12};
        <<2#0101:4, _:4>> -> {1488, 16};
        <<2#0110:4, _:4>> -> {1860, 20};
        <<2#1001:4, _:4>> -> {512, 5};
        <<2#1010:4, _:4>> -> {768, 7.5};
        <<2#1011:4, _:4>> -> {1024, 10};
        <<2#1100:4, _:4>> -> {1536, 15};
        <<2#1101:4, _:4>> -> {2048, 20}
    end,
    Di = case TA1 of
        none -> 1;
        <<_:4, 2#0001:4>> -> 1;
        <<_:4, 2#0010:4>> -> 2;
        <<_:4, 2#0011:4>> -> 4;
        <<_:4, 2#0100:4>> -> 8;
        <<_:4, 2#0101:4>> -> 16;
        <<_:4, 2#0110:4>> -> 32;
        <<_:4, 2#0111:4>> -> 64;
        <<_:4, 2#1000:4>> -> 12;
        <<_:4, 2#1001:4>> -> 20
    end,
    GuardN = case TC1 of
        none -> 0;
        <<V>> -> V
    end,
    Intfs0 = #{
        fi => Fi, fmax => Fmax, di => Di, guardn => GuardN
    },
    {Intfs1, Rest4} = case HasTD of
        1 -> decode_next_intf(Intfs0, Rest3);
        0 -> {Intfs0, Rest3}
    end,
    <<HistBytes:K/binary, _/binary>> = Rest4,
    Intfs2 = decode_hist_bytes(Intfs1, HistBytes),
    Intfs2.

-ifdef(TEST).

decode_tlv_invalid_tag_test() ->
    D = <<16#5F>>,
    R = decode_ber_tlvs(D),
    ?assertMatch({error, _}, R).

decode_tlv_short_length_test() ->
    D = <<16#01, 16#FF, 16#00>>,
    R = decode_ber_tlvs(D),
    ?assertMatch({error, _}, R).

decode_tlv_one_byte_tag_test() ->
    D = <<16#4F, 16#0B, 16#A0, 16#00, 16#00, 16#03, 16#08, 16#00, 16#00,
          16#10, 16#00, 16#01, 16#00>>,
    R = decode_ber_tlvs(D),
    ?assertMatch({ok, [{16#4F, B}]} when is_binary(B), R).

decode_tlv_two_byte_tag_test() ->
    D = <<16#5F, 16#2F, 16#02, 16#00, 16#00>>,
    R = decode_ber_tlvs(D),
    ?assertMatch({ok, [{16#5F2F, <<0, 0>>}]}, R).

decode_tlv_long_len_test() ->
    D = <<16#01, 16#81, 200, 0:200/unit:8,
          16#02, 16#82, 1024:16/big, 0:1024/unit:8>>,
    R = decode_ber_tlvs(D),
    ?assertMatch(
        {ok, [ {16#01, B}, {16#02, B2} ]} when
            (byte_size(B) == 200) and (byte_size(B2) == 1024),
        R).

-define(test_tag_map, #{
        16#61 => {apt, #{
            16#4F => aid,
            16#50 => app_label,
            16#79 => {alloc_auth, #{
                16#4F => aid
            }},
            16#5F50 => uri,
            16#AC => {algos, #{
                16#80 => [algo],
                16#06 => oid
            }}
        }}
    }).

decode_tlv_map_test() ->
    TagMap = ?test_tag_map,
    D = base64:decode(<<"YX5PC6AAAAMIAAAQAAEAeQ1PC6AAAAMIAAAQAAEAUBpQaXZBcHBsZX"
        "QgdjAuOC4yL1JFZVBTQXhhRF9QJmh0dHBzOi8vZ2l0aHViLmNvbS9hcmVraW5hdGgvUGl2"
        "QXBwbGV0rBuAAQOAAQiAAQqAAQyAAQaAAQeAARGAARQGAQA=">>),
    Ret = decode_ber_tlvs_map(D, TagMap),
    ?assertMatch({ok, _}, Ret),
    {ok, Map} = Ret,
    ?assertMatch(#{apt := #{
        aid := _, app_label := <<"PivApplet v0.8.2/REePSAxaD">>,
        algos := #{
            oid := <<0>>,
            algo := [_|_]
            }
        }}, Map),
    #{apt := #{algos := #{algo := AlgList}}} = Map,
    ?assertMatch([<<3>> | _], AlgList).

inv_map_test() ->
    TagMap = ?test_tag_map,
    InvTagMap = invert_tlv_map(TagMap),
    ?assertMatch(#{
        apt := {16#61, #{
            aid := 16#4F,
            app_label := 16#50,
            alloc_auth := {16#79, #{
                aid := 16#4F
            }},
            algos := {16#AC, #{
                algo := [16#80],
                oid := 16#06
            }}
        }}
    }, InvTagMap).

encode_tlv_map_test() ->
    TagMap = ?test_tag_map,
    Map = #{
        apt => #{
            aid => <<1,2,3,4>>,
            app_label => <<"Testing">>,
            uri => <<"https://test.com">>,
            algos => #{
                algo => [<<1>>, <<2>>, <<3>>]
            }
        }
    },
    D = encode_ber_tlvs_map(Map, invert_tlv_map(TagMap)),
    {ok, Map2} = decode_ber_tlvs_map(D, TagMap),
    ?assertMatch(Map, Map2),
    ?assertMatch(
        <<"YS1PBAECAwSsCYABAYABAoABA1AHVGVzdGluZ19QEGh0dHBzOi8vdGVzdC5jb20=">>,
        base64:encode(D)).

encode_tlv_ordered_map_test() ->
    TagMap = #{
        16#01 => {aaa, #{
            16#80 => zzz
        }},
        16#02 => [bbb],
        16#03 => ccc
    },
    InvTagMap = [
        {bbb, [16#02]},
        {aaa, {16#01, #{
            zzz => 16#80
        }}},
        {ccc, 16#03}
    ],
    Map = #{
        aaa => #{ zzz => <<"test">> },
        bbb => [ <<"b1">>, <<"b2">> ],
        ccc => <<"c0">>
    },
    D = encode_ber_tlvs_map(Map, InvTagMap),
    {ok, Map2} = decode_ber_tlvs_map(D, TagMap),
    ?assertMatch(Map, Map2),
    ?assertMatch(
        <<16#02, 2, "b1", 16#02, 2, "b2",
          16#01, 6, 16#80, 4, "test",
          16#03, 2, "c0">>, D).

-endif.
