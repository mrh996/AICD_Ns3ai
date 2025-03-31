# Copyright (c) 2025 University of Liverpool
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2 as
# published by the Free Software Foundation;
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
#
# Author: Ronghui Mu <ronghui.mu@liverpool.ac.uk>
# Author: Jinwei Hu <jinwei.hu@liverpool.ac.uk>
# Author: Valerio Selis <v.selis@liverpool.ac.uk>

import numpy as np
import torch
import torch.nn as nn
from stable_baselines3.common.torch_layers import BaseFeaturesExtractor
from stable_baselines3.common.policies import ActorCriticPolicy


class Config:
    def __init__(self,
                 algo,
                 patch_dim,
                 num_blocks,
                 features_dim,
                 embed_dim_inner,
                 num_heads_inner,
                 attention_dropout_inner,
                 ffn_dropout_inner,
                 context_len_inner,
                 embed_dim_outer,
                 num_heads_outer,
                 attention_dropout_outer,
                 ffn_dropout_outer,
                 context_len_outer,
                 observation_type,
                 C, H, W, D,
                 activation_fn_inner,
                 activation_fn_outer,
                 activation_fn_other,
                 dim_expand_inner,
                 dim_expand_outer,
                 have_position_encoding,
                 share_tit_blocks):
        self.algo = algo
        self.patch_dim = patch_dim
        self.num_blocks = num_blocks
        self.features_dim = features_dim
        self.embed_dim_inner = embed_dim_inner
        self.num_heads_inner = num_heads_inner
        self.attention_dropout_inner = attention_dropout_inner
        self.ffn_dropout_inner = ffn_dropout_inner
        self.context_len_inner = context_len_inner
        self.embed_dim_outer = embed_dim_outer
        self.num_heads_outer = num_heads_outer
        self.attention_dropout_outer = attention_dropout_outer
        self.ffn_dropout_outer = ffn_dropout_outer
        self.context_len_outer = context_len_outer
        self.observation_type = observation_type
        self.obs_C, self.obs_H, self.obs_W, self.obs_D = C, H, W, D
        self.obs_C = 1  # if observation has C channels, we think it has 1 channel with context_len_outer==C
        self.activation_fn_inner = activation_fn_inner
        self.activation_fn_outer = activation_fn_outer
        self.activation_fn_other = activation_fn_other
        self.dim_expand_inner = dim_expand_inner
        self.dim_expand_outer = dim_expand_outer
        self.have_position_encoding = have_position_encoding
        self.share_tit_blocks = share_tit_blocks


class InnerTransformerBlock(nn.Module):
    def __init__(self, config):
        super(InnerTransformerBlock, self).__init__()
        self.ln1 = nn.LayerNorm(config.embed_dim_inner)
        self.attention = nn.MultiheadAttention(
            embed_dim=config.embed_dim_inner,
            num_heads=config.num_heads_inner,
            dropout=config.attention_dropout_inner,
            batch_first=True,
        )
        self.ln2 = nn.LayerNorm(config.embed_dim_inner)
        self.ffn = nn.Sequential(
            nn.Linear(config.embed_dim_inner, config.dim_expand_inner * config.embed_dim_inner),
            config.activation_fn_inner(),
            nn.Linear(config.dim_expand_inner * config.embed_dim_inner, config.embed_dim_inner),
            nn.Dropout(config.ffn_dropout_inner),
        )

    def forward(self, x):
        x_ln1 = self.ln1(x)
        attn_outputs, attn_weights = self.attention(query=x_ln1, key=x_ln1, value=x_ln1)
        x = x + attn_outputs

        x_ln2 = self.ln2(x)
        ffn_outputs = self.ffn(x_ln2)
        x = x + ffn_outputs
        return x


class OuterTransformerBlock(nn.Module):
    def __init__(self, config):
        super(OuterTransformerBlock, self).__init__()
        self.ln1 = nn.LayerNorm(config.embed_dim_outer)
        self.attention = nn.MultiheadAttention(
            embed_dim=config.embed_dim_outer,
            num_heads=config.num_heads_outer,
            dropout=config.attention_dropout_outer,
            batch_first=True,
        )
        self.ln2 = nn.LayerNorm(config.embed_dim_outer)
        self.ffn = nn.Sequential(
            nn.Linear(config.embed_dim_outer, config.dim_expand_outer * config.embed_dim_outer),
            config.activation_fn_outer(),
            nn.Linear(config.dim_expand_outer * config.embed_dim_outer, config.embed_dim_outer),
            nn.Dropout(config.ffn_dropout_outer),
        )

        # Set up causal masking for attention
        ones = torch.ones(config.context_len_outer, config.context_len_outer)
        self.attention_mask = nn.Parameter(torch.triu(ones, diagonal=1), requires_grad=False)
        self.attention_mask[self.attention_mask.bool()] = -float('inf')
        # The mask will look like:
        # [0, -inf, -inf, ..., -inf]
        # [0,    0, -inf, ..., -inf]
        # ...
        # [0,    0,    0, ...,    0]
        # Where 0 means that timestep is allowed to attend. ==>  For a float mask,
        # the mask values will be added to the attention weight.  ==>
        # https://pytorch.org/docs/stable/generated/torch.nn.MultiheadAttention.html
        # So the first timestep can attend only to the first timestep
        # and the last timestep can attend to all observations.

    def forward(self, x):
        x_ln1 = self.ln1(x)
        attn_outputs, attn_weights = self.attention(query=x_ln1, key=x_ln1, value=x_ln1,
                                                    attn_mask=self.attention_mask[:x.size(1), :x.size(1)])
        x = x + attn_outputs

        x_ln2 = self.ln2(x)
        ffn_outputs = self.ffn(x_ln2)
        x = x + ffn_outputs
        return x


class EnhancedBlock(nn.Module):
    def __init__(self, config):
        super(EnhancedBlock, self).__init__()
        self.inner_Transformer_block = InnerTransformerBlock(config)
        self.outer_Transformer_block = OuterTransformerBlock(config)

        self.K = config.context_len_outer
        self.context_len_inner = config.context_len_inner
        self.embed_dim_inner = config.embed_dim_inner

    def forward(self, inner_tokens):
        # inner_tokens has a shape of (new_B, context_len_inner+1, embed_dim_inner) where new_B = B * context_len_outer
        inner_outputs = self.inner_Transformer_block(inner_tokens)

        # outer_tokens has a shape of (B, context_len_outer, embed_dim_outer)
        # for TIT, embed_dim_outer==embed_dim_inner
        temp = inner_outputs.view(-1, self.K, self.context_len_inner+1, self.embed_dim_inner)  # -1 -> B
        outer_tokens = temp[:, :, 0, :]  # 0 means class_tokens, which serve as the input of outer block
        outer_outputs = self.outer_Transformer_block(outer_tokens)

        return inner_outputs, outer_outputs


class TIT(nn.Module):
    def __init__(self, config):
        super(TIT, self).__init__()
        self.config = config

        # Input
        if config.observation_type == 'image':
            # We map each observation patch into the observation patch embedding with a trainable linear projection
            self.obs_patch_embed = nn.Conv2d(
                in_channels=config.obs_C,
                out_channels=config.embed_dim_inner,
                kernel_size=config.patch_dim,
                stride=config.patch_dim,
                bias=False,
            )
        elif config.observation_type == 'array':
            self.obs_patch_embed = nn.Conv1d(
                in_channels=1,
                out_channels=config.embed_dim_inner,
                kernel_size=config.patch_dim,
                stride=config.patch_dim,
                bias=False,
                padding=int(np.ceil((config.context_len_inner * config.patch_dim - config.obs_D) / 2))
            )
        else:
            raise ValueError('observation must be an 3d-image or 1d-array')

        # The patch position encoding is a trainable parameter
        self.class_token_encoding = nn.Parameter(torch.zeros(1, 1, config.embed_dim_inner))
        if self.config.have_position_encoding:
            self.obs_patch_pos_encoding = nn.Parameter(torch.zeros(1, config.context_len_inner+1, config.embed_dim_inner))

        # TiT blocks
        if config.algo in ['vanilla_tit_ppo', 'vanilla_tit_cql']:
            self.inner_blocks = nn.ModuleList([InnerTransformerBlock(config) for _ in range(config.num_blocks)])
            self.outer_blocks = nn.ModuleList([OuterTransformerBlock(config) for _ in range(config.num_blocks)])
        elif config.algo in ['enhanced_tit_ppo', 'enhanced_tit_cql']:
            if self.config.share_tit_blocks:
                self.block = EnhancedBlock(config)  # share parameters between layers
            else:
                self.blocks = nn.ModuleList([EnhancedBlock(config) for _ in range(config.num_blocks)])
            # self.ln1s = nn.ModuleList([nn.LayerNorm(config.embed_dim_outer) for _ in range(config.num_blocks)])
        else:
            raise ValueError('model_type must be Vanilla_TIT, Fused_TIT or Enhanced_TIT')

        # Head
        if config.algo in ['vanilla_tit_ppo', 'vanilla_tit_cql']:
            self.ln1 = nn.LayerNorm(config.embed_dim_outer)
            self.head = nn.Sequential(
                nn.Linear(config.embed_dim_outer, config.features_dim),
                config.activation_fn_other()
            )
            self.ln2 = nn.LayerNorm(config.features_dim)
        elif config.algo in ['enhanced_tit_ppo', 'enhanced_tit_cql']:
            self.ln1 = nn.LayerNorm(config.embed_dim_outer * config.num_blocks)
            self.head = nn.Sequential(
                nn.Linear(config.embed_dim_outer * config.num_blocks, config.features_dim),
                config.activation_fn_other()
            )
            self.ln2 = nn.LayerNorm(config.features_dim)

        nn.init.trunc_normal_(self.class_token_encoding, mean=0.0, std=0.02)
        if self.config.have_position_encoding:
            nn.init.trunc_normal_(self.obs_patch_pos_encoding, mean=0.0, std=0.02)
        self.apply(self._init_weights)

    def _image_observation_patch_embedding(self, obs):
        B, context_len_outer, C, H, W = obs.size()
        B = B * context_len_outer  # new_B
        obs = obs.contiguous().view(B, C, H, W)
        obs_patch_embedding = self.obs_patch_embed(obs)  # shape is (new_B, out_C, out_H, out_W),
        # where out_C=embed_dim_inner, out_H*out_W=context_len_inner
        obs_patch_embedding = obs_patch_embedding.view(B, self.config.embed_dim_inner, self.config.context_len_inner)
        obs_patch_embedding = obs_patch_embedding.transpose(2, 1)  # (new_B, context_len_inner, embed_dim_inner)
        return obs_patch_embedding

    def _array_observation_patch_embedding(self, obs):
        B, context_len_outer, D = obs.size()
        B = B * context_len_outer  # new_B
        obs = obs.view(B, D)
        obs = torch.unsqueeze(obs, dim=1)  # (new_B, 1, D), first apply unsqueeze() before applying Conv1d()
        obs_patch_embedding = self.obs_patch_embed(obs)  # shape is (new_B, out_C, out_length),
        # where out_C=embed_dim_inner, out_length=context_len_inner
        obs_patch_embedding = obs_patch_embedding.transpose(2, 1)  # (new_B, context_len_inner, embed_dim_inner)
        return obs_patch_embedding

    def _init_weights(self, module):
        if isinstance(module, (nn.Linear, nn.Embedding)):
            nn.init.trunc_normal_(module.weight, mean=0.0, std=0.02)
            if isinstance(module, nn.Linear) and module.bias is not None:
                nn.init.zeros_(module.bias)
        elif isinstance(module, nn.LayerNorm):
            torch.nn.init.zeros_(module.bias)
            torch.nn.init.ones_(module.weight)

    def forward(self, obs):
        if self.config.observation_type == 'image':
            # print('obs.size() ==>', obs.size())  # we use make_atari_env(n_envs=8), so the size is  (8, 4, 84, 84)
            obs = obs.unsqueeze(dim=2)
            # print('obs.size() ==>', obs.size())  # (8, 4, 1, 84, 84)  4_frames_stack means the context_len_outer=4
            B, context_len_outer, C, H, W = obs.size()
            new_B = B * context_len_outer

            obs_patch_embedding = self._image_observation_patch_embedding(obs)
            inner_tokens = torch.cat([self.class_token_encoding.expand(new_B, -1, -1), obs_patch_embedding], dim=1)
            if self.config.have_position_encoding:
                inner_tokens = inner_tokens + self.obs_patch_pos_encoding
            # inner_tokens has a shape of (new_B, context_len_inner+1, embed_dim_inner)

        elif self.config.observation_type == 'array':
            # print('obs.size() ==>', obs.size())  # (1, 4)
            obs = obs.unsqueeze(dim=1)
            # print('obs.size() ==>', obs.size())  # (1, 1, 4)
            B, context_len_outer, D = obs.size()
            new_B = B * context_len_outer
            obs_patch_embedding = self._array_observation_patch_embedding(obs)
            inner_tokens = torch.cat([self.class_token_encoding.expand(new_B, -1, -1), obs_patch_embedding], dim=1)
            if self.config.have_position_encoding:
                inner_tokens = inner_tokens + self.obs_patch_pos_encoding
            # inner_tokens has a shape of (new_B, context_len_inner+1, embed_dim_inner)

        # inner_tokens has a shape of (new_B, context_len_inner+1, embed_dim_inner)
        # outer_tokens has a shape of (B, context_len_outer, embed_dim_outer)

        if self.config.algo in ['vanilla_tit_ppo', 'vanilla_tit_cql']:
            for inner_block in self.inner_blocks:
                inner_tokens = inner_block(inner_tokens)

            temp = inner_tokens.view(B, context_len_outer, self.config.context_len_inner+1, self.config.embed_dim_inner)
            outer_tokens = temp[:, :, 0, :]  # 0 means class_tokens, which serve as the input of outer block
            for outer_block in self.outer_blocks:
                outer_tokens = outer_block(outer_tokens)

            x = outer_tokens[:, -1, :]  # only return the last element of outer_block for decision-making
            x = self.ln2(self.head(self.ln1(x)))  # (B, embed_dim_outer)

        elif self.config.algo in ['enhanced_tit_ppo', 'enhanced_tit_cql']:
            # if self.config.observation_type == 'array' and self.config.patch_dim > 1:
            #     all_outer_outputs = [inner_tokens[:, -1, :]]
            # else:
            all_outer_outputs = []
            if self.config.share_tit_blocks:
                for i in range(self.config.num_blocks):
                    inner_tokens, outer_outputs = self.block(inner_tokens)
                    all_outer_outputs.append(outer_outputs[:, -1, :])
            else:
                for block in self.blocks:
                    inner_tokens, outer_outputs = block(inner_tokens)
                    all_outer_outputs.append(outer_outputs[:, -1, :])

            x = torch.cat(all_outer_outputs, dim=-1)
            x = self.ln2(self.head(self.ln1(x)))  # (B, embed_dim_outer)

        return x


class TitFeaturesExtractor(BaseFeaturesExtractor):
    # https://stable-baselines3.readthedocs.io/en/master/guide/custom_policy.html#custom-feature-extractor
    # features_dim: Number of features extracted. This corresponds to the number of unit for the last layer.
    def __init__(self, observation_space,
                 algo,
                 patch_dim, num_blocks, features_dim,
                 embed_dim_inner, num_heads_inner, attention_dropout_inner, ffn_dropout_inner,
                 embed_dim_outer, num_heads_outer, attention_dropout_outer, ffn_dropout_outer,
                 activation_fn_inner, activation_fn_outer, activation_fn_other,
                 dim_expand_inner, dim_expand_outer, have_position_encoding, share_tit_blocks):
        super(TitFeaturesExtractor, self).__init__(observation_space, features_dim)

        C, H, W, D = 0, 0, 0, 0
        if len(observation_space.shape) == 3:  # (4, 84, 84)
            observation_type = 'image'
            print('observation_type = image')
            C, H, W = observation_space.shape
            assert (H % patch_dim == 0) and (W % patch_dim == 0)
            context_len_inner = (H // patch_dim) * (W // patch_dim)
            n_stack = 4
            context_len_outer = n_stack
        elif len(observation_space.shape) == 1:  # (27,)
            observation_type = 'array'
            print('observation_type = array')
            D = observation_space.shape[0]
            # patch_dim = 1
            # assert patch_dim == 1
            # context_len_inner = D // patch_dim
            context_len_inner = int(np.ceil(D / patch_dim))
            n_stack = 1
            context_len_outer = n_stack
        else:
            raise ValueError('len(observation_space.shape) should either be 1 or 3')
        config = Config(algo,
                        patch_dim,
                        num_blocks,
                        features_dim,
                        embed_dim_inner,
                        num_heads_inner,
                        attention_dropout_inner,
                        ffn_dropout_inner,
                        context_len_inner,
                        embed_dim_outer,
                        num_heads_outer,
                        attention_dropout_outer,
                        ffn_dropout_outer,
                        context_len_outer,
                        observation_type,
                        C, H, W, D,
                        activation_fn_inner,
                        activation_fn_outer,
                        activation_fn_other,
                        dim_expand_inner,
                        dim_expand_outer,
                        have_position_encoding,
                        share_tit_blocks)
        self.pure_transformer_backbone = TIT(config)

    def forward(self, observations: torch.Tensor) -> torch.Tensor:
        return self.pure_transformer_backbone(observations)
