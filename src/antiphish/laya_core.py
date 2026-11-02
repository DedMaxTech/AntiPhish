"""Laya inference architecture, adapted from the Apache-2.0 upstream implementation.

Source: https://huggingface.co/convaiinnovations/laya/tree/7b928d828b7b0e022f929d9bd2e44165aa270148
See THIRD_PARTY_NOTICES.md. Imported only when this optional model is requested.
"""
import torch
from torch import nn


class DecisionModel(nn.Module):
    def __init__(self, encoder, head_layers=2):
        super().__init__()
        self.encoder=encoder
        d=encoder.config.hidden_size
        layer=nn.TransformerEncoderLayer(d,max(1,d//64),4*d,.1,batch_first=True,norm_first=True)
        self.head=nn.TransformerEncoder(layer,head_layers,enable_nested_tensor=False)
        self.type_emb=nn.Embedding(3,d)
        self.scorer=nn.Sequential(nn.LayerNorm(d),nn.Linear(d,d),nn.GELU(),nn.Linear(d,1))
        self.act_head=nn.Sequential(nn.Linear(d+4,256),nn.GELU(),nn.Linear(256,2))
        self.register_buffer('temperature',torch.ones(3))

    def forward(self,ids,mask,markers,marker_mask,qtypes):
        h=self.encoder(input_ids=ids,attention_mask=mask).last_hidden_state
        h=h+self.type_emb(qtypes)[:,None,:]
        for layer in self.head.layers:h=layer(h,src_key_padding_mask=~mask.bool())
        selected=torch.gather(h,1,markers[:,:,None].expand(-1,-1,h.size(-1)))
        return self.scorer(selected).squeeze(-1).float().masked_fill(~marker_mask,-1e4)


def sequence(tokenizer,text,instructions,options,qtype,max_len=1024):
    mask=tokenizer.mask_token
    head=tokenizer(qtype+' question: '+instructions.replace(mask,' '),add_special_tokens=False)['input_ids']
    opts=[[tokenizer.mask_token_id]+tokenizer(' '+s.replace(mask,' '),add_special_tokens=False)['input_ids'][:48] for s in options]
    budget=256-sum(map(len,opts))
    if budget<16:raise ValueError('Decision options exceed the head budget')
    ids=[tokenizer.cls_token_id]+head[:max(8,budget)]+[tokenizer.sep_token_id]
    markers=[]
    for opt in opts:markers.append(len(ids));ids.extend(opt)
    ids.append(tokenizer.sep_token_id)
    body=tokenizer(text.replace(mask,' '),add_special_tokens=False)['input_ids']
    room=max_len-len(ids)-1
    return ids+body[:room]+[tokenizer.sep_token_id],markers,room
