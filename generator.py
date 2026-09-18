import argparse
import secrets
import string
import sys

AMBIGUOUS = "Il1O0"


def build_charset(no_symbols, no_numbers, no_uppercase, no_lowercase, exclude_ambiguous):
    charset = ""

    if not no_lowercase:
        charset += string.ascii_lowercase
    if not no_uppercase:
        charset += string.ascii_uppercase
    if not no_numbers:
        charset += string.digits
    if not no_symbols:
        charset += "!@#$%^&*()-_=+[]{};:,.<>?"

    if exclude_ambiguous:
        charset = "".join(c for c in charset if c not in AMBIGUOUS)

    return charset


def generate_password(length, charset):
    if not charset:
        raise ValueError("Nenhum conjunto de caracteres disponível para gerar a senha.")
    return "".join(secrets.choice(charset) for _ in range(length))


def estimate_strength(length, charset_size):
    import math
    if charset_size == 0 or length == 0:
        return "N/A"
    bits = length * math.log2(charset_size)
    if bits < 40:
        return "fraca"
    if bits < 60:
        return "média"
    if bits < 80:
        return "forte"
    return "muito forte"


def main():
    parser = argparse.ArgumentParser(description="Gerador de senhas seguras via linha de comando.")
    parser.add_argument("-l", "--length", type=int, default=16, help="tamanho da senha (padrão: 16)")
    parser.add_argument("-c", "--count", type=int, default=1, help="quantidade de senhas a gerar (padrão: 1)")
    parser.add_argument("--no-symbols", action="store_true", help="não incluir símbolos")
    parser.add_argument("--no-numbers", action="store_true", help="não incluir números")
    parser.add_argument("--no-uppercase", action="store_true", help="não incluir letras maiúsculas")
    parser.add_argument("--no-lowercase", action="store_true", help="não incluir letras minúsculas")
    parser.add_argument("--exclude-ambiguous", action="store_true", help="excluir caracteres ambíguos (I, l, 1, O, 0)")

    args = parser.parse_args()

    if args.length < 4:
        print("O comprimento mínimo recomendado é 4.", file=sys.stderr)
        sys.exit(1)

    charset = build_charset(
        args.no_symbols,
        args.no_numbers,
        args.no_uppercase,
        args.no_lowercase,
        args.exclude_ambiguous,
    )

    if not charset:
        print("Nenhum conjunto de caracteres restante. Ajuste as flags e tente novamente.", file=sys.stderr)
        sys.exit(1)

    strength = estimate_strength(args.length, len(charset))

    for _ in range(args.count):
        print(generate_password(args.length, charset))

    print(f"\nForça estimada: {strength}", file=sys.stderr)


if __name__ == "__main__":
    main()
