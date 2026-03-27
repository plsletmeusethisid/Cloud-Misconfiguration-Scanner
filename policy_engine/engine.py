from policy_engine.tokenizer import tokenize
from policy_engine.parser import parse
from policy_engine.evaluator import evaluate


def run_policy(policy_str, resource):
    tokens = tokenize(policy_str)
    ast = parse(tokens)
    return evaluate(ast, resource)
