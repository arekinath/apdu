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

%% @private
-module(apdu_xform_test_3).

-behaviour(apdu_transform).

-export([
    formats/0,
    init/2,
    begin_transaction/1,
    command/2,
    reply/2,
    end_transaction/1,
    terminate/1
    ]).

formats() -> {foo, bar}.

-record(?MODULE, {}).

init(_, []) -> {ok, #?MODULE{}}.

terminate(#?MODULE{}) -> ok.

begin_transaction(S0 = #?MODULE{}) -> {ok, S0}.

end_transaction(S0 = #?MODULE{}) -> {ok, leave, S0}.

command(foo_cmd, S0 = #?MODULE{}) ->
    {ok, [bar_cmd], S0}.

reply(bar_reply, S0 = #?MODULE{}) ->
    {ok, [bar2_cmd], [foo_progress], S0};
reply(bar2_reply, S0 = #?MODULE{}) ->
    {ok, [foo_reply], S0}.
