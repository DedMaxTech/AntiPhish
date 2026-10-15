"""Russian text normalization for analysis; never rewrite operational URLs."""
import re
import unicodedata

_CONFUSABLES = str.maketrans({
    'A':'А','B':'В','C':'С','E':'Е','H':'Н','K':'К','M':'М','O':'О','P':'Р','T':'Т','X':'Х',
    'a':'а','c':'с','e':'е','o':'о','p':'р','x':'х','y':'у',
    'Α':'А','Β':'В','Ε':'Е','Η':'Н','Κ':'К','Μ':'М','Ο':'О','Ρ':'Р','Τ':'Т','Χ':'Х',
    'α':'а','ο':'о','ρ':'р','κ':'к','χ':'х',
})


def normalize_russian(text):
    text = unicodedata.normalize('NFKC',text)
    text = ''.join(c for c in text if unicodedata.category(c) not in {'Cf','Mn'})
    def word(match):
        value = match.group(0)
        return value.translate(_CONFUSABLES) if re.search('[А-Яа-яЁё]',value) else value
    return re.sub(r'[^\W\d_]+',word,text,flags=re.UNICODE)
