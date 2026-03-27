import re

TOKEN_REGEX = r'==|AND|OR|NOT|EXISTS|WHERE|\(|\)|[A-Za-z_\.]+|".*?"|\d+|true|false'


def tokenize(policy):
    return [t.strip() for t in re.findall(TOKEN_REGEX, policy) if t.strip()]
