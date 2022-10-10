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
    start_link/2
    ]).

-type mod() :: apdu_transform:mod().
-type modlist() :: [mod() | {mod(), [term()]}].

%% @doc Starts a stack of APDU transforms and links them up.
-spec start_link(apdu:protocol(), modlist()) -> {ok, pid()} | {error, term()}.
start_link(Proto, ModList) ->
    case start_xforms(Proto, ModList) of
        {ok, Pids} ->
            case link_xforms(Pids) of
                ok -> {ok, Pids};
                Err -> Err
            end;
        Err ->
            Err
    end.

start_xforms(_, []) -> {ok, []};
start_xforms(Proto, [{Mod, Args} | Rest]) when is_atom(Mod) and is_list(Args) ->
    case apdu_transform:start_link(Mod, Proto, Args) of
        {ok, Pid} ->
            case start_xforms(Proto, Rest) of
                {ok, RestPids} ->
                    {ok, [Pid | RestPids]};
                Err ->
                    Err
            end;
        Err ->
            Err
    end;
start_xforms(Proto, [Mod | Rest]) when is_atom(Mod) ->
    case apdu_transform:start_link(Mod, Proto, []) of
        {ok, Pid} ->
            case start_xforms(Proto, Rest) of
                {ok, RestPids} ->
                    {ok, [Pid | RestPids]};
                Err ->
                    Err
            end;
        Err ->
            Err
    end.

link_xforms([_Last]) -> ok;
link_xforms([A, B | Rest]) ->
    case apdu_transform:connect(A, B) of
        ok -> link_xforms([B | Rest]);
        Err -> Err
    end.
