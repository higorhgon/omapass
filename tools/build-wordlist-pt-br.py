#!/usr/bin/env python3
"""Monta a lista de palavras pt-BR do gerador de frases do omapass.

A fonte é o corpus https://github.com/fserb/pt-br (MIT, Fernando Serboncini):

    cd /tmp && for f in lexico icf listas/negativas listas/paises \\
        listas/estados-br listas/municipios-br listas/continentes; do
        curl -sL -O "https://raw.githubusercontent.com/fserb/pt-br/master/$f"
    done
    python3 tools/build-wordlist-pt-br.py /tmp wordlists/pt-BR.wordlist

Os critérios seguem os da lista EFF que o KeePassXC usa, adaptados ao
português:

- 7776 palavras (6^5), uma jogada de cinco dados por palavra e 12,9 bits de
  entropia cada;
- de 4 a 9 letras, só a-z: sem acento e sem ç, porque a frase é digitada em
  campos de senha, às vezes em outro teclado;
- as mais comuns primeiro, pela pontuação do arquivo `icf` (quanto menor,
  mais comum), para que a frase seja fácil de ler e digitar;
- nenhuma palavra é prefixo de outra, então a frase continua sem ambiguidade
  mesmo sem separador — o lugar da regra de prefixo único da lista EFF, que
  em português deixaria só 2514 palavras (contra 10788 com quatro letras);
- fora as palavras da lista `negativas` do corpus e os nomes de lugares
  (países, estados, municípios e continentes).
"""

import sys
import unicodedata
from pathlib import Path

WORDS = 7776
MIN_LENGTH = 4
MAX_LENGTH = 9
PLACE_LISTS = ("paises", "estados-br", "municipios-br", "continentes")


def strip_accents(word: str) -> str:
    decomposed = unicodedata.normalize("NFD", word)
    return "".join(c for c in decomposed if unicodedata.category(c) != "Mn")


def read_lines(path: Path) -> list[str]:
    return [line.strip().lower() for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


def main() -> int:
    source = Path(sys.argv[1] if len(sys.argv) > 1 else ".")
    target = Path(sys.argv[2] if len(sys.argv) > 2 else "wordlists/pt-BR.wordlist")

    banned = {strip_accents(word) for word in read_lines(source / "negativas")}
    for name in PLACE_LISTS:
        path = source / name
        if not path.exists():
            print(f"faltando {path}", file=sys.stderr)
            return 1
        for line in read_lines(path):
            banned.update(strip_accents(line).split())

    # icf: "palavra,pontuação" — quanto menor, mais comum é a palavra.
    ranking: dict[str, float] = {}
    for line in (source / "icf").read_text(encoding="utf-8").splitlines():
        word, _, score = line.partition(",")
        if word and score:
            ranking.setdefault(word, float(score))

    candidates = {
        word
        for word in (w.strip().lower() for w in (source / "lexico").read_text(encoding="utf-8").split())
        if MIN_LENGTH <= len(word) <= MAX_LENGTH
        and word.isascii()
        and word.isalpha()
        and word not in banned
        and word in ranking
    }

    chosen: list[str] = []
    taken: set[str] = set()
    for word in sorted(candidates, key=lambda w: (ranking[w], w)):
        # Nem a palavra começa com uma já escolhida, nem o contrário.
        if any(word[:length] in taken for length in range(MIN_LENGTH, len(word))):
            continue
        if any(other.startswith(word) for other in taken):
            continue

        taken.add(word)
        chosen.append(word)
        if len(chosen) == WORDS:
            break

    if len(chosen) < WORDS:
        print(f"apenas {len(chosen)} palavras passaram nos critérios", file=sys.stderr)
        return 1

    chosen.sort()
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text("\n".join(chosen) + "\n", encoding="utf-8")
    print(f"{len(chosen)} palavras em {target} (mais rara: {chosen and max(chosen, key=ranking.get)})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
