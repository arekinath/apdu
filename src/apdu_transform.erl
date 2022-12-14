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

%% @doc Behaviour for APDU transforms.
-module(apdu_transform).

-export_type([mod/0, format/0]).

-type cmd_raw() :: term().
%% The type of an outgoing command after this transform has been applied to it
%% (ready for the next transformation below this one in the direction of raw
%% bytes)

-type cmd_cooked() :: term().
%% The type of an outgoing command received by this transform module.

-type reply_raw() :: term().
%% The type of an incoming command received by this transform module from
%% the previous transformation below this one (closer to raw bytes).

-type reply_cooked() :: term().
%% The type of an incoming command after this transform module has been
%% applied.

-type state() :: term().
%% Internal state of the transform module.

-type mod() :: module().
%% The name of a module which implements this behaviour.

-type format() :: atom().
%% A name for a "format": a type of data processed by an APDU transform.

-callback formats() -> {Cooked :: format() | [format()], Raw :: format() | [format()]}.
%% Returns atoms identifying the type of data which this module can
%% accept and produce.

-callback init(apdu:protocol(), [term()]) -> {ok, state()} | {error, term()}.
%% Initialise the transformation, returning an initial state.

-callback begin_transaction(state()) -> {ok, state()} | {error, term()}.
%% Called at the beginning of a card transaction.

-callback command(cmd_cooked(), state()) ->
    {ok, [cmd_raw()], state()} | {ok, [reply_cooked()], [cmd_raw()], state()} |
    {ok, state()} | {error, term()}.
%% Transform a command into output commands or replies.

-callback reply(reply_raw(), state()) ->
    {ok, [reply_cooked()], state()} | {ok, [cmd_raw()], [reply_cooked()], state()} |
    {ok, state()} | {error, term()}.
%% Transform a reply into cooked replies or further commands.

-callback end_transaction(apdu:disposition(), state()) ->
    {ok, apdu:disposition(), state()} | {error, term()}.
%% Called at the end of a card transaction. The first argument is the current
%% proposed disposition.

-callback terminate(state()) -> ok.


-export([
    start_link/3,
    connect/2,
    command/2,
    commands/2,
    begin_transaction/1,
    end_transaction/1,
    end_transaction/2,
    max_dispos/1
]).

-export([
    init/1, terminate/2,
    handle_call/3,
    handle_cast/2
]).

-spec start_link(mod(), apdu:protocol(), [term()]) -> {ok, pid()} | {error, term()}.
start_link(Mod, Proto, Args) ->
    case code:which(Mod) of
        non_existing ->
            {error, {bad_module, Mod}};
        _ ->
            case code:is_loaded(Mod) of
                false ->
                    _ = code:load_file(Mod);
                _ ->
                    ok
            end,
            case {erlang:function_exported(Mod, formats, 0),
                  erlang:function_exported(Mod, command, 2)} of
                {false, _} ->
                    {error, {not_apdu_transform, Mod}};
                {_, false} ->
                    {error, {not_apdu_transform, Mod}};
                _ ->
                    gen_server:start_link(?MODULE, [Mod, Proto, Args], [])
            end
    end.

-spec connect(pid(), pid()) -> ok | {error, term()}.
connect(Pid, NextPid) ->
    gen_server:call(Pid, {connect, NextPid}).

-spec command(pid(), cmd_cooked()) -> {ok, [reply_cooked()]} | {error, term()}.
command(Pid, Cmd0) ->
    gen_server:call(Pid, {command, Cmd0}, infinity).

%% @private
-spec commands(pid(), [cmd_cooked()]) -> {ok, [reply_cooked()]} | {error, term()}.
commands(_Pid, []) ->
    {ok, []};
commands(Pid, [Cmd | Rest]) ->
    case gen_server:call(Pid, {command, Cmd}, infinity) of
        {ok, Replies0} ->
            case commands(Pid, Rest) of
                {ok, RestReplies} ->
                    {ok, Replies0 ++ RestReplies};
                Err ->
                    Err
            end;
        Err ->
            Err
    end.

-spec begin_transaction(pid()) -> ok | {error, term()}.
begin_transaction(Pid) ->
    gen_server:call(Pid, begin_transaction, infinity).

-spec end_transaction(pid()) ->
    {ok, apdu:disposition()} | {error, term()}.
end_transaction(Pid) ->
    gen_server:call(Pid, {end_transaction, leave}, infinity).

%% @private
-spec end_transaction(pid(), apdu:disposition()) ->
    {ok, apdu:disposition()} | {error, term()}.
end_transaction(Pid, Dispos) ->
    gen_server:call(Pid, {end_transaction, Dispos}, infinity).

-record(?MODULE, {
    mod :: atom(),
    modstate :: term(),
    next :: undefined | pid()
}).

%% @private
init([Mod, Proto, Args]) ->
    case Mod:init(Proto, Args) of
        {ok, ModState0} ->
            {ok, #?MODULE{mod = Mod, modstate = ModState0}};
        Err ->
            {stop, Err}
    end.

%% @private
terminate(_Why, #?MODULE{mod = Mod, modstate = ModState0}) ->
    ok = Mod:terminate(ModState0).

down_commands(Cmds, S0 = #?MODULE{next = Next}) ->
    case apdu_transform:commands(Next, Cmds) of
        {ok, Replies} ->
            up_replies(Replies, S0);
        Err ->
            Err
    end.
up_replies([], S0) ->
    {ok, [], S0};
up_replies([Reply | Rest], S0 = #?MODULE{mod = Mod, modstate = MS0}) ->
    case Mod:reply(Reply, MS0) of
        {ok, Replies, MS1} ->
            S1 = S0#?MODULE{modstate = MS1},
            case up_replies(Rest, S1) of
                {ok, RestReplies, S2} ->
                    {ok, Replies ++ RestReplies, S2};
                Err ->
                    Err
            end;
        {ok, Cmds, Replies, MS1} ->
            S1 = S0#?MODULE{modstate = MS1},
            case down_commands(Cmds, S1) of
                {ok, MoreReplies, S2} ->
                    case up_replies(Rest, S2) of
                        {ok, RestReplies, S3} ->
                            {ok, Replies ++ MoreReplies ++ RestReplies, S3};
                        Err ->
                            Err
                    end;
                Err ->
                    Err
            end;
        {ok, MS1} ->
            {ok, [], S0#?MODULE{modstate = MS1}};
        Err ->
            Err
    end.

%% @private
handle_call(get_formats, _From, S0 = #?MODULE{mod = Mod}) ->
    {reply, {ok, Mod:formats()}, S0};

handle_call({connect, Pid}, _From, S0 = #?MODULE{mod = Mod}) ->
    OurFormats = Mod:formats(),
    case gen_server:call(Pid, get_formats, infinity) of
        {ok, NextFormats} ->
            case check_formats(OurFormats, NextFormats) of
                ok ->
                    {reply, ok, S0#?MODULE{next = Pid}};
                Err ->
                    {reply, Err, S0}
            end;
        Err ->
            {reply, Err, S0}
    end;

handle_call({command, Cmd0}, From, S0 = #?MODULE{mod = Mod, modstate = MS0}) ->
    case Mod:command(Cmd0, MS0) of
        {ok, MS1} ->
            {reply, {ok, []}, S0#?MODULE{modstate = MS1}};
        {ok, Cmds1, MS1} ->
            S1 = S0#?MODULE{modstate = MS1},
            case down_commands(Cmds1, S1) of
                {ok, Replies, S2} ->
                    {reply, {ok, Replies}, S2};
                Err ->
                    gen_server:reply(From, Err),
                    {stop, Err, S1}
            end;
        {ok, Replies, [], MS1} ->
            S1 = S0#?MODULE{modstate = MS1},
            {reply, {ok, Replies}, S1};
        {ok, Replies, Cmds1, MS1} ->
            S1 = S0#?MODULE{modstate = MS1},
            case down_commands(Cmds1, S1) of
                {ok, NextReplies, S2} ->
                    {reply, {ok, Replies ++ NextReplies}, S2};
                Err ->
                    gen_server:reply(From, Err),
                    {stop, Err, S1}
            end;
        Err ->
            gen_server:reply(From, Err),
            {stop, Err, S0}
    end;

handle_call(begin_transaction, From, S0 = #?MODULE{mod = Mod, modstate = MS0,
                                                   next = Next}) ->
    case Mod:begin_transaction(MS0) of
        {ok, MS1} when (Next =:= undefined) ->
            {reply, ok, S0#?MODULE{modstate = MS1}};
        {ok, MS1} ->
            Reply = apdu_transform:begin_transaction(Next),
            {reply, Reply, S0#?MODULE{modstate = MS1}};
        Err ->
            gen_server:reply(From, Err),
            {stop, Err, S0}
    end;

handle_call({end_transaction, D}, From, S0 = #?MODULE{mod = Mod, modstate = MS0,
                                                      next = Next}) ->
    case Mod:end_transaction(D, MS0) of
        {ok, Dispos, MS1} when (Next =:= undefined) ->
            Dispos1 = max_dispos([D, Dispos]),
            {reply, {ok, Dispos1}, S0#?MODULE{modstate = MS1}};
        {ok, Dispos, MS1} ->
            Dispos1 = max_dispos([D, Dispos]),
            case apdu_transform:end_transaction(Next, Dispos1) of
                {ok, NextDispos} ->
                    {reply, {ok, NextDispos}, S0#?MODULE{modstate = MS1}};
                Err ->
                    {reply, Err, S0#?MODULE{modstate = MS1}}
            end;
        Err ->
            gen_server:reply(From, Err),
            {stop, Err, S0}
    end.

%% @private
handle_cast(Msg, S0 = #?MODULE{}) ->
    {stop, {bad_cast, Msg}, S0}.

max_dispos(A, []) -> A;
max_dispos(A, [A | Rest]) -> max_dispos(A, Rest);
max_dispos(reset, [leave | Rest]) -> max_dispos(reset, Rest);
max_dispos(unpower, [leave | Rest]) -> max_dispos(unpower, Rest);
max_dispos(unpower, [reset | Rest]) -> max_dispos(unpower, Rest);
max_dispos(eject, [leave | Rest]) -> max_dispos(eject, Rest);
max_dispos(eject, [reset | Rest]) -> max_dispos(eject, Rest);
max_dispos(eject, [unpower | Rest]) -> max_dispos(eject, Rest);
max_dispos(_A, [Any | Rest]) -> max_dispos(Any, Rest).

%% @doc Returns the strictest of a list of dispositions.
-spec max_dispos([apdu:disposition()]) -> apdu:disposition().
max_dispos([A | Rest]) -> max_dispos(A, Rest).

check_formats({_CookedA, RawA}, {CookedB, _RawB}) ->
    RawASet = sets:from_list(if
        is_list(RawA) -> RawA;
        true -> [RawA]
    end),
    CookedBSet = sets:from_list(if
        is_list(CookedB) -> CookedB;
        true -> [CookedB]
    end),
    case sets:is_disjoint(RawASet, CookedBSet) of
        true ->
            {error, {no_common_formats, RawA, CookedB}};
        false ->
            ok
    end.

-ifdef(TEST).
-include_lib("eunit/include/eunit.hrl").

max_dispos_test() ->
    ?assertMatch(reset, max_dispos([reset, leave])),
    ?assertMatch(unpower, max_dispos([reset, leave, unpower])),
    ?assertMatch(unpower, max_dispos([unpower, leave, reset])),
    ?assertMatch(eject, max_dispos([unpower, eject])),
    ?assertMatch(eject, max_dispos([unpower, eject, leave, reset])).

check_formats_test() ->
    ?assertMatch(ok, check_formats({foo, bar}, {bar, test})),
    ?assertMatch(ok, check_formats({[foo, xyz, thing], [bar, abc]},
                                   {[abc, thing], [test]})),
    ?assertMatch({error, _}, check_formats({foo, bar}, {[foo, xyz, test], abc})),
    ?assertMatch({error, _}, check_formats({foo, [bar, abc]}, {[foo, xyz, test], abc})).

test_xform_test() ->
    {ok, Pid1} = apdu_transform:start_link(apdu_xform_test_1, t1, []),
    {ok, Pid2} = apdu_transform:start_link(apdu_xform_test_2, t1, []),
    ?assertMatch({error, _}, apdu_transform:connect(Pid2, Pid1)),
    ?assertMatch(ok, apdu_transform:connect(Pid1, Pid2)),
    ?assertMatch(ok, apdu_transform:begin_transaction(Pid1)),
    ?assertMatch({ok, [foo_reply]}, apdu_transform:command(Pid1, foo_cmd)),
    ?assertMatch({ok, eject}, apdu_transform:end_transaction(Pid1)).

test_xform2_test() ->
    {ok, [Pid1, _Pid2]} = apdu_stack:start_link(t1,
        [apdu_xform_test_3, apdu_xform_test_2]),
    ?assertMatch(ok, apdu_transform:begin_transaction(Pid1)),
    ?assertMatch({ok, [foo_progress, foo_reply]}, apdu_transform:command(Pid1, foo_cmd)),
    ?assertMatch({ok, reset}, apdu_transform:end_transaction(Pid1)).

stack_err_test() ->
    Res0 = apdu_stack:start_link(t1, [apdu_xform_test_3, nonexistent_module]),
    ?assertMatch({error, _}, Res0),
    Res1 = apdu_stack:start_link(t1, [apdu_xform_test_1, apdu_xform_test_3]),
    ?assertMatch({error, _}, Res1).

-endif.
