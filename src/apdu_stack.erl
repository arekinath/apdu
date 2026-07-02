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

%% @doc A helper module for using a "stack" of APDU transforms.
-module(apdu_stack).

-export([
    start_link/2,
    start_monitor/2,
    stop/1
    ]).

-type mod() :: apdu_transform:mod().
-type modlist() :: [mod() | {mod(), [term()]}].

%% @doc Starts a stack of APDU transforms and links them up.
-spec start_link(apdu:protocol(), modlist()) -> {ok, [pid()]} | {error, term()}.
start_link(Proto, ModList) ->
    maybe
        {ok, Pids} ?= start_link_xforms(Proto, ModList),
        ok ?= link_xforms(Pids),
        {ok, Pids}
    end.

-spec start_monitor(apdu:protocol(), modlist()) -> {ok, [{pid(), reference()}]} | {error, term()}.
start_monitor(Proto, ModList) ->
    maybe
        {ok, PidRefs} ?= start_monitor_xforms(Proto, ModList),
        ok ?= link_xforms([Pid || {Pid, _Ref} <- PidRefs]),
        {ok, PidRefs}
    end.

-spec stop([pid()] | [{pid(), reference()}]) -> ok | {error, term()}.
stop([]) -> ok;
stop([{Pid, Ref} | Rest]) ->
    ok = apdu_transform:stop(Pid),
    receive
        {'DOWN', Ref, process, Pid, _} -> ok
    end,
    stop(Rest);
stop([Pid | Rest]) ->
    ok = apdu_transform:stop(Pid),
    stop(Rest).

start_monitor_xforms(_, []) -> {ok, []};
start_monitor_xforms(Proto, [Mod | Rest]) when is_atom(Mod) ->
    start_monitor_xforms(Proto, [{Mod, []} | Rest]);
start_monitor_xforms(Proto, [{Mod, Args} | Rest]) when is_atom(Mod) and is_list(Args) ->
    maybe
        {ok, {Pid, Ref}} ?= apdu_transform:start_monitor(Mod, Proto, Args),
        {ok, RestPidRefs} ?= start_monitor_xforms(Proto, Rest),
        {ok, [{Pid, Ref} | RestPidRefs]}
    end.

start_link_xforms(_, []) -> {ok, []};
start_link_xforms(Proto, [Mod | Rest]) when is_atom(Mod) ->
    start_link_xforms(Proto, [{Mod, []} | Rest]);
start_link_xforms(Proto, [{Mod, Args} | Rest]) when is_atom(Mod) and is_list(Args) ->
    maybe
        {ok, Pid} ?= apdu_transform:start_link(Mod, Proto, Args),
        {ok, RestPids} ?= start_link_xforms(Proto, Rest),
        {ok, [Pid | RestPids]}
    end.

link_xforms([_Last]) -> ok;
link_xforms([A, B | Rest]) ->
    case apdu_transform:connect(A, B) of
        ok -> link_xforms([B | Rest]);
        Err -> Err
    end.
