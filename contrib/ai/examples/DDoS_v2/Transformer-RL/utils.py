# BSD 3-Clause License
#
# Copyright (c) 2025, University of Liverpool
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are met:
#
# 1. Redistributions of source code must retain the above copyright notice, this
#    list of conditions and the following disclaimer.
#
# 2. Redistributions in binary form must reproduce the above copyright notice,
#    this list of conditions and the following disclaimer in the documentation
#    and/or other materials provided with the distribution.
#
# 3. Neither the name of the copyright holder nor the names of its
#    contributors may be used to endorse or promote products derived from
#    this software without specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
# AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
# DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
# FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
# DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
# SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
# CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
# OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
# OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
#
# Author: Ronghui Mu <ronghui.mu@liverpool.ac.uk>
# Author: Jinwei Hu <jinwei.hu@liverpool.ac.uk>
# Author: Valerio Selis <v.selis@liverpool.ac.uk>

import os
import json
import torch.nn as nn
import yaml
# from network import TitFeaturesExtractor, ResnetFeaturesExtractor, CatformerFeaturesExtractor
from network import TitFeaturesExtractor


def linear_schedule(initial_value: float):
    # https://stable-baselines3.readthedocs.io/en/master/guide/examples.html#learning-rate-schedule
    def func(progress_remaining: float) -> float:
        return progress_remaining * initial_value
    return func


def update_args(args, hyperparams=None):
    if hyperparams is None:
        yaml_file = './hyperparameter_final_' + args.algo + '.yaml'
        with open(yaml_file) as f:
            hyperparams_dict = yaml.safe_load(f)
            if args.env_name in list(hyperparams_dict.keys()):
                hyperparams = hyperparams_dict[args.env_name]
            else:
                raise ValueError(f'Hyperparameters not found for {args.algo}-{args.env_name}')
        print('the loaded hyperparams ==>', hyperparams)
    else:
        print('the given hyperparams ==>', hyperparams)

    args.n_timesteps = hyperparams['n_timesteps']
    args.patch_dim = hyperparams['patch_dim']
    args.num_blocks = hyperparams['num_blocks']
    args.features_dim = hyperparams['features_dim']
    args.embed_dim_inner = hyperparams['embed_dim_inner']
    args.num_heads_inner = hyperparams['num_heads_inner']
    args.attention_dropout_inner = hyperparams['attention_dropout_inner']
    args.ffn_dropout_inner = hyperparams['ffn_dropout_inner']
    args.embed_dim_outer = hyperparams['embed_dim_outer']
    args.num_heads_outer = hyperparams['num_heads_outer']
    args.attention_dropout_outer = hyperparams['attention_dropout_outer']
    args.ffn_dropout_outer = hyperparams['ffn_dropout_outer']
    activation_fn = {'tanh': nn.Tanh, 'relu': nn.ReLU, 'gelu': nn.GELU}
    args.activation_fn_inner = activation_fn[hyperparams['activation_fn_inner']]
    args.activation_fn_outer = activation_fn[hyperparams['activation_fn_outer']]
    args.activation_fn_other = activation_fn[hyperparams['activation_fn_other']]
    args.dim_expand_inner = hyperparams['dim_expand_inner']
    args.dim_expand_outer = hyperparams['dim_expand_outer']
    args.have_position_encoding = hyperparams['have_position_encoding']
    args.share_tit_blocks = hyperparams['share_tit_blocks']
    print('the updated args ==>', args)

    return args


def load_policy_kwargs(args):
    # if args.algo == 'resnet_ppo':
    #     policy_kwargs = dict(
    #         features_extractor_class=ResnetFeaturesExtractor,
    #         features_extractor_kwargs=dict(features_dim=512),
    #         net_arch=[],
    #     )
    # elif args.algo == 'catformer_ppo':
    #     policy_kwargs = dict(
    #         features_extractor_class=CatformerFeaturesExtractor,
    #         features_extractor_kwargs=dict(features_dim=512),
    #         net_arch=[],
    #     )
    # else:
    if args.algo in ['enhanced_tit_ppo', 'vanilla_tit_ppo']:  # vanilla_tit and enhanced_tit
        policy_kwargs = dict(
            features_extractor_class=TitFeaturesExtractor,
            features_extractor_kwargs=dict(
                algo=args.algo,
                patch_dim=args.patch_dim,
                num_blocks=args.num_blocks,
                features_dim=args.features_dim,
                embed_dim_inner=args.embed_dim_inner,
                num_heads_inner=args.num_heads_inner,
                attention_dropout_inner=args.attention_dropout_inner,
                ffn_dropout_inner=args.ffn_dropout_inner,
                embed_dim_outer=args.embed_dim_outer,
                num_heads_outer=args.num_heads_outer,
                attention_dropout_outer=args.attention_dropout_outer,
                ffn_dropout_outer=args.ffn_dropout_outer,
                activation_fn_inner=args.activation_fn_inner,
                activation_fn_outer=args.activation_fn_outer,
                activation_fn_other=args.activation_fn_other,
                dim_expand_inner=args.dim_expand_inner,
                dim_expand_outer=args.dim_expand_outer,
                have_position_encoding=args.have_position_encoding,
                share_tit_blocks=args.share_tit_blocks,
            ),
            net_arch=[],
        )
    return policy_kwargs
