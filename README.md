# omapass

[![CI](https://github.com/higorhgon/omapass/actions/workflows/ci.yml/badge.svg)](https://github.com/higorhgon/fpass/actions/workflows/ci.yml)

Gerenciador de senhas com interface Qt Quick, escrito em C++, que segue o tema
do Omarchy, a fonte monoespaçada do sistema e o modo claro/escuro
automaticamente. Suporta quatro backends: **KeePassXC** (.kdbx, via
`keepassxc-cli`), **pass** — the standard unix password manager (via `gpg`) —,
**Bitwarden** (via o CLI oficial `bw`) e **1Password** (via o CLI oficial
`op`).

Feito na mesma linha do [omacalc](https://github.com/omacom-io/omacalc),
[omawrite](https://github.com/omacom-io/omawrite) e
[omacut](https://github.com/omacom-io/omacut): Qt 6 + QML, cores lidas do tema
ativo do Omarchy e retintadas ao vivo quando o tema muda.

## Funcionalidades

- Suporte a KeePassXC e a pass — o omapass detecta ambos automaticamente e adapta a interface a cada um (entradas do pass, por exemplo, têm só Título e Senha, sem Usuário/URL/Notas no formulário)
- No pass, o omapass guarda a passphrase só durante a sessão e decifra as entradas com ela
- Contas Bitwarden (bitwarden.com) com login pela própria interface, incluindo verificação em duas etapas e verificação de novo dispositivo
- Desbloqueio opcional por PIN, um PIN por banco, em qualquer backend
- Contas 1Password com login pela própria interface (endereço, e-mail, Secret Key, senha mestra e, quando houver, código de duas etapas), com os cofres virando grupos e as etiquetas aninhadas abaixo deles
- Seletor de banco de dados com busca multi-termo e navegação estilo vim
- Modal integrado para desbloqueio de banco com validação de senha/passphrase
- Criação de bancos pela própria interface: KeePassXC (nome + senha), pass (diretório com autocomplete + escolha de chave GPG existente) ou conta Bitwarden/1Password (login)
- Listagem, adição, edição, exclusão e renomeação de grupos/entradas
- Gerador de senhas e de frases (diceware) em modal próprio, que copia ou preenche o campo Senha do formulário
- Modal de ajuda com todos os atalhos (`Ctrl+?`)
- Motor de frecency (frequência + recência) para ordenação inteligente
- Cores vindas do tema do Omarchy, com sobreposição opcional por tema próprio em TOML
- Atalhos de teclado: `j/k`, `gg/G`, `Ctrl+U/D`, `/` para buscar — os mesmos da versão TUI
- Suporte a mouse: clique, duplo-clique e botão direito na lista; seleção de texto nos detalhes da entrada

## Requisitos

- Qt 6: `qt6-base`, `qt6-declarative`
- `xdg-desktop-portal` e um backend de portal (para o modo claro/escuro e o tamanho de texto do desktop)
- `wl-clipboard` (`wl-copy`) para copiar senhas
- Para o desbloqueio por PIN (opcional, em qualquer banco): `secret-tool`, do `libsecret`, e um chaveiro do sistema destravado — o Omarchy já traz os dois. Sem isso, a opção de PIN simplesmente não aparece.
- Botan 3 (`botan` no Arch/Omarchy, `libbotan-3-dev` no Debian/Ubuntu) — usado para abrir contas Bitwarden sem passar pelo `bw`, e já exigido para compilar o `keepassxc-cli`

Para bancos **KeePassXC**:

- `./bin/build` já compila um `keepassxc-cli` a partir do submodule vendorizado em `vendor/keepassxc` (um fork somente-CLI do KeePassXC) e `sudo make install` o deixa no PATH junto do `omapass` — não é preciso instalar o KeePassXC completo. Isso exige, na máquina que compila: `cmake`, Botan, ZLIB, Minizip, PCSC, libusb, readline e Qt 6 (Core/Concurrent/Gui/Test).
- Alternativamente, qualquer `keepassxc-cli` (do pacote oficial do KeePassXC, por exemplo) já disponível no PATH também funciona.

Para bancos **pass**:

- [`pass`](https://www.passwordstore.org/) instalado
- `gpg`/`gpg-agent`, com pelo menos uma chave secreta já criada (veja [Configurando o pass](#configurando-o-pass))
- `gpg-agent` configurado para aceitar a senha via loopback (`allow-loopback-pinentry`) — necessário porque o omapass decifra entradas passando a passphrase pelo stdin do `gpg`, sem abrir um pinentry a cada acesso

Para contas **Bitwarden**:

- [`bitwarden-cli`](https://bitwarden.com/help/cli/) (o comando `bw`) no PATH — no Arch/Omarchy, `sudo pacman -S bitwarden-cli`. Sem ele, a opção Bitwarden não aparece no menu de novo banco.

Para contas **1Password**:

- [`1password-cli`](https://developer.1password.com/docs/cli/) (o comando `op`) no PATH — no Arch/Omarchy, `sudo pacman -S 1password-cli`. Sem ele, a opção 1Password não aparece no menu de novo banco.
- Uma conta em que você possa usar a senha mestra e a Secret Key (as contas que entram só por SSO não têm senha mestra, e o `op` não as adiciona desse jeito).
- `script`, do `util-linux` (já presente em qualquer instalação): o `op` só pergunta o código de verificação em duas etapas quando está falando com um terminal, então o omapass empresta um a ele. Sem o `script`, contas **sem** duas etapas continuam abrindo normalmente.

A busca por bancos usa [`fd`](https://github.com/sharkdp/fd) quando disponível
(bem mais rápido em um diretório home inteiro) e cai para uma varredura própria
quando não está instalado.

## Instalação

```bash
git clone --recurse-submodules https://github.com/higorhgon/omapass.git
cd omapass
make
```

(Se já clonou sem `--recurse-submodules`, rode `git submodule update --init` antes de `make`.)

O binário fica em `build/omapass`, e o `keepassxc-cli` compilado do submodule em
`build/keepassxc-cli`. Os testes rodam com `make test`.

Para instalar no sistema (padrão `PREFIX=/usr/local`):

```bash
sudo make install
```

ou para instalar em `~/.local`:

```bash
make install PREFIX="$HOME/.local"
```

Isso também instala o `keepassxc-cli` compilado do submodule em `$(BINDIR)`; se
o KeePassXC completo já estiver instalado no sistema, essa cópia pode
sombreá-lo no PATH dependendo da ordem de `$PATH` — é o comportamento
pretendido (usar a variante somente-CLI no lugar da instalação completa).

Para desinstalar:

```bash
sudo make uninstall
```

`PREFIX` e `DESTDIR` são configuráveis, por exemplo `make install PREFIX=/usr DESTDIR="$pkgdir"` para empacotamento.

## Uso

```bash
./build/omapass
```

O programa busca automaticamente, dentro do diretório configurado (`path` em
`config.toml`, padrão: home directory):

- arquivos `.kdbx` (bancos KeePassXC)
- diretórios contendo `.gpg-id` (password-stores do pass)

além das contas Bitwarden e 1Password adicionadas pelo omapass, se houver, e exibe
uma interface interativa para seleção, desbloqueio e gestão de senhas, indicando o
tipo de cada banco encontrado (`[KeePassXC]`, `[pass]`, `[Bitwarden]` ou
`[1Password]`). Havendo um único banco, ele vai direto para o modal de desbloqueio.

### Criando um banco pela interface

Na tela de seleção, `Ctrl+A` abre um menu perguntando o tipo de banco a criar:

- **KeePassXC** — pede nome do arquivo e senha mestra; o banco é criado em `~/.config/omapass/databases/`.
- **pass** — pede o diretório de destino (com autocomplete dos nomes de pasta existentes) e uma chave GPG dentre as já presentes no seu chaveiro. O omapass não gera chaves GPG novas — veja a seção abaixo para criar uma.
- **Bitwarden** — aparece só com o `bw` instalado. Pede e-mail e senha mestra da sua conta; veja [Usando o Bitwarden](#usando-o-bitwarden).
- **1Password** — aparece só com o `op` instalado. Pede endereço, e-mail, Secret Key e senha mestra; veja [Usando o 1Password](#usando-o-1password).

### Usando o Bitwarden

O omapass conversa com o Bitwarden pelo `bw`, então a conta fica logada no próprio
`bw` (o mesmo login que `bw status` mostra no terminal). Só **bitwarden.com** é
suportado — servidores próprios (Vaultwarden, self-hosted) não.

- **Adicionando a conta**: `Ctrl+A` → **Bitwarden** → e-mail e senha mestra. Se a conta
  usa verificação em duas etapas, o omapass pede o código em seguida (com vários
  métodos cadastrados, pergunta antes qual usar: aplicativo autenticador, e-mail ou
  YubiKey). Num dispositivo novo, o Bitwarden manda um código por e-mail, que é pedido
  do mesmo jeito. Se o `bw` já estiver logado pelo terminal, a conta é só adicionada
  à lista e pede a senha mestra. O `bw` mantém **uma** conta por vez, então o omapass avisa
  se você tentar adicionar outra sem sair da atual.
- **Abrindo**: a conta aparece na lista com o e-mail; abrir pede só a senha mestra.
  O omapass decifra sozinho a cópia local cifrada que o próprio `bw` mantém
  (`~/.config/Bitwarden CLI/data.json`), sem iniciar o `bw` — a lista aparece em
  uma fração de segundo, e funciona sem internet. Se o arquivo estiver num formato
  que o omapass não reconhece (uma versão nova do `bw`, contas com criptografia
  mais nova, SSO sem senha mestra), ele abre pelo `bw` como antes, só mais devagar. A sincronização com o servidor
  (`bw sync`) roda em seguida, em segundo plano, junto com o desbloqueio do `bw` que
  as alterações precisam; o rodapé indica enquanto isso acontece, e alterações
  esperam terminar. Se o `bw` tiver sido deslogado por fora,
  o omapass volta ao login com o e-mail já preenchido.
- **Pastas viram grupos**: uma pasta `Trabalho/Email` é o grupo `Trabalho/Email`.
  Só itens do tipo **login** aparecem — cartões, identidades, notas seguras e chaves
  SSH ficam de fora. Itens com o mesmo nome na mesma pasta ganham o começo do id
  entre colchetes (`Email [1a2b3c4d]`) para se distinguirem.
- **Editar preserva o resto**: o formulário mexe em nome, pasta, usuário, senha,
  primeira URL e notas; TOTP, campos personalizados e as demais URLs do item ficam
  como estavam.
- **Excluir manda para a lixeira** do Bitwarden (recuperável pelo cofre web por 30 dias).
- **Saindo da conta**: `Ctrl+X` sobre a conta na tela de bancos faz `bw logout`, tira a conta
  da lista e apaga o PIN guardado, se houver.

- Cada comando do `bw` leva alguns segundos (é um programa Node). Por isso o cofre
  inteiro é carregado uma vez ao abrir — copiar, ver detalhes e editar são
  instantâneos — e as operações que precisam do `bw` (abrir, salvar, excluir,
  renomear) rodam em segundo plano, sem travar a janela.

### Desbloqueio por PIN

Vale para **qualquer banco**, com um PIN por banco: um para o `.kdbx` do trabalho, outro para
a conta Bitwarden, outro para o 1Password. Com o banco aberto, `Ctrl+I` ativa o desbloqueio
por PIN (e desativa, quando já está ativo). Ele pede a senha do banco uma vez — a senha mestra,
ou a passphrase GPG no caso do pass — e um PIN de pelo menos 4 caracteres. A partir daí, a tela
de desbloqueio daquele banco pede o PIN; `Tab` volta para a senha a qualquer momento.

Por padrão o PIN é só de dígitos, mas a opção **Permitir letras e símbolos** no mesmo modal
abre o alfabeto — e isso muda muito o que ele protege, porque o PIN é a única coisa entre o
dado guardado e quem o ler. Com 6 caracteres:

| alfabeto | combinações |
|---|---|
| só dígitos | 1.000.000 |
| dígitos e letras minúsculas | ~2,2 bilhões |
| com maiúsculas e símbolos | ~690 bilhões |

O aviso abaixo do campo aparece enquanto o PIN der menos de um milhão de combinações — o que
seis dígitos dão —, contando o alfabeto que ele realmente usa. Então `1234` avisa, `abcd`
(456.976) também, e `k7$w` não.

A senha é conferida antes de ser guardada, sem abrir o banco de novo (abrir custaria uma sessão
nova no Bitwarden e no 1Password). A única exceção é o 1Password, que não tem como conferir
localmente: ali uma senha errada só aparece no primeiro desbloqueio por PIN, que então remove
o PIN e pede a senha.

O PIN vale entre sessões e depois de reiniciar a máquina. Ele é removido quando você desativa
com `Ctrl+I`, erra 5 vezes seguidas, sai da conta (`Ctrl+X`), ou quando a senha guardada deixa
de abrir o banco — por exemplo depois de trocar a senha mestra, quando o omapass pede a nova.

Quem já usava o PIN só do Bitwarden não precisa refazer nada: o PIN guardado é movido para a
chave nova na primeira vez que o banco é aberto.

### Usando o 1Password

O omapass conversa com o 1Password pelo `op`, e a lista de bancos é montada a partir do
que `op account list` mostra — não há uma cópia à parte. Quantas contas você tiver no `op`,
tantas aparecem, e uma adicionada (ou removida) pelo terminal aparece (ou some) sozinha.

- **Adicionando uma conta**: `Ctrl+A` → **1Password** → endereço (já vem preenchido com
  `my.1password.com`, o padrão do 1Password), e-mail, Secret Key, senha mestra e, se quiser,
  um **apelido**. Se a conta usa verificação em duas etapas, o omapass pede o código em
  seguida — tanto ao adicionar a conta quanto ao abri-la depois, já que o 1Password pede o
  código a cada nova sessão. O apelido é o `--shorthand` do `op` e é como a conta aparece na lista; deixando
  em branco, o omapass usa a parte do e-mail antes do @ (com um número no fim, se já houver
  outra conta com esse nome). Isso porque o `op`, sozinho, nomearia a conta a partir do
  endereço — `my` —, o que não diz de quem ela é. Contas adicionadas pelo terminal sem
  apelido aparecem pelo e-mail.
- **Abrindo**: abrir faz `op signin` e lista cofres e itens. A sessão do `op` expira depois
  de 30 minutos sem uso; quando isso acontece, o omapass avisa e volta a pedir a senha
  mestra — ele não guarda a senha depois de abrir.
- **Cofres viram grupos, etiquetas aninham abaixo**: um item no cofre `Pessoal` com a
  etiqueta `Trabalho/Email` aparece em `Pessoal/Trabalho/Email`. Um item com várias
  etiquetas aparece pela primeira em ordem alfabética; mover a entrada troca só essa
  etiqueta, e as outras ficam como estavam. Renomear ou apagar um grupo de primeiro nível
  mexe no cofre (`op vault edit`/`op vault delete`); nos demais níveis, mexe nas etiquetas
  dos itens daquele cofre.
- **Só logins e senhas** aparecem — cartões, identidades, notas seguras e chaves SSH ficam
  de fora, porque o formulário do omapass (título, usuário, senha, URL e notas) não daria
  conta de reescrevê-los. Itens com o mesmo título no mesmo grupo ganham o começo do id
  entre colchetes (`Netflix [1a2b3c4d]`).
- **Editar preserva o resto**: o formulário mexe em título, etiqueta, usuário, senha,
  primeira URL e notas; seções, campos personalizados, OTP e as demais URLs ficam como
  estavam. Entradas com **passkey** são somente-leitura no omapass: o `op` não sabe
  reescrever uma passkey a partir de um template, e editar a destruiria — use o aplicativo
  do 1Password para essas.
- **Excluir manda para "Excluídos recentemente"** (recuperável pelos aplicativos do
  1Password por 30 dias).
- **Saindo de uma conta**: `Ctrl+X` sobre ela na tela de bancos apaga os dados da conta
  deste computador — e, por consequência, a tira da lista. Qual comando faz isso depende de
  haver uma sessão aberta (`op signout --forget` quando há, `op account forget` quando não),
  então o omapass tenta os dois e só diz que desconectou depois de conferir que o `op` parou
  de listar a conta. As outras contas continuam onde estavam.
- Cada comando do `op` é rápido (é um binário Go, com um daemon que guarda os itens
  cifrados em memória), mas cada um fala com o servidor. Por isso a listagem é carregada
  ao abrir e as senhas são buscadas na primeira vez que aparecem, ficando em memória
  enquanto o cofre está aberto; tudo isso roda em segundo plano, sem travar a janela.

### Configurando o pass

Se preferir configurar por fora da interface (ou ainda não tiver uma chave GPG):

**1. Gere uma chave GPG**, caso ainda não tenha uma:

```bash
gpg --full-generate-key
```

Siga os prompts (tipo e tamanho da chave, validade, nome, e-mail e senha). Para conferir as chaves disponíveis depois:

```bash
gpg --list-secret-keys --keyid-format long
```

**2. Inicialize um password-store** com essa chave:

```bash
pass init <SEU-GPG-KEY-ID>
```

Isso cria o store em `~/.password-store`. Para criar em outro lugar, defina `PASSWORD_STORE_DIR` antes de rodar o comando:

```bash
PASSWORD_STORE_DIR=/caminho/personalizado pass init <SEU-GPG-KEY-ID>
```

O omapass encontra automaticamente qualquer diretório com `.gpg-id` dentro do seu diretório de busca configurado (veja `path` em [Configuração](#configuração)) — é possível ter múltiplos password-stores em locais diferentes.

**3. Permita que o gpg-agent aceite a senha via loopback**, para o omapass poder decifrar entradas com a passphrase que já pediu uma vez:

```bash
echo "allow-loopback-pinentry" >> ~/.gnupg/gpg-agent.conf
gpg-connect-agent reloadagent /bye
```

> **Nota:** no pass, o omapass só expõe **Título** e **Senha** no formulário de adicionar/editar — o formato do pass é bem menos estruturado que o do KeePassXC. Campos como usuário/URL/notas de uma entrada já existente são preservados ao editá-la, mesmo sem aparecer no formulário.

### Migrando um banco KeePassXC para o pass

```bash
omapass --kdbx2pass banco.kdbx KEYID1 [KEYID2...]
```

Roda no terminal, sem abrir janela. Inicializa (ou reaponta) o password-store
padrão para os `KEYID`s informados e importa cada entrada do `.kdbx`, pedindo a
senha mestra uma única vez. Username/URL/Notas viram metadados nas linhas
seguintes à senha, no formato convencional do pass; nada é gravado em disco em
texto puro durante o processo.

### Gerando senhas

Com um banco aberto, `Ctrl+G` (ou **Gerar senha** no menu de ações) abre o gerador. Ele tem
dois modos:

- **Senha** — tamanho, maiúsculas, minúsculas, números, símbolos, evitar caracteres parecidos
  (`l/1/I`, `O/0`), excluir caracteres específicos e um conjunto personalizado, que substitui
  as classes.
- **Frase** — número de palavras e separador. A lista segue o idioma da interface: em
  português usa a lista pt-BR do omapass, e em inglês a lista EFF que vem do KeePassXC, ambas
  com 7.776 palavras (12,9 bits de entropia por palavra).

A senha é gerada de novo a cada ajuste, e `Ctrl+R` sorteia outra sem mudar nada. `Enter` copia
para a área de transferência, com a mesma limpeza automática de 10 segundos das entradas. Dentro
do formulário de entrada, `Ctrl+G` sobre o campo Senha abre o mesmo gerador e `Enter` preenche o
campo em vez de copiar. As escolhas ficam guardadas para a próxima vez.

O gerador é sempre o `keepassxc-cli`, mesmo em bancos do pass ou do Bitwarden: ele responde em
cerca de 10 ms, enquanto o `bw generate` leva uns 2,5 s por senha (é um programa Node) e o
`pass generate` não gera sem criar uma entrada. As listas de palavras são instaladas pelo
`make install` em `$(PREFIX)/share/omapass/wordlists`; rodando direto de `build/`, elas são lidas
do repositório e do submodule. Sem lista alguma, o modo frase não aparece.

Para escolher outra lista, use `wordlist` no `config.toml`:

```toml
[generator]
# "auto" (padrão) segue o idioma da interface; "pt-BR" ou "en" escolhem uma
# das listas que acompanham o omapass; qualquer outra coisa é um caminho.
wordlist = "auto"
```

Uma lista própria é um arquivo de texto com uma palavra por linha (o formato numerado
`11111 palavra` do diceware também é aceito). Apontar para um arquivo que não existe deixa o
modo frase indisponível, em vez de cair silenciosamente na lista padrão.

A lista **pt-BR** foi montada a partir do corpus [fserb/pt-br](https://github.com/fserb/pt-br)
(MIT, Fernando Serboncini) pelo script `tools/build-wordlist-pt-br.py`, que documenta os
critérios: 7.776 palavras de 4 a 9 letras, sem acento, as mais comuns primeiro, sem nomes de
lugares nem palavras ofensivas, e nenhuma palavra sendo prefixo de outra.

## Segurança

- **Backend KeePassXC**: a senha da entrada é sempre passada ao `keepassxc-cli` via stdin, mas `keepassxc-cli` não aceita usuário/URL/notas por stdin — esses campos vão como argumentos (`-u`, `--url`, `--notes`) em `add`/`edit`. Isso é uma limitação do `keepassxc-cli`, não do omapass: durante a execução do processo, outro usuário local com acesso a `/proc/<pid>/cmdline` (ou `ps aux`) pode ler esses valores. A senha em si nunca passa por argv. O backend **pass** não tem essa limitação — toda a entrada (senha e metadados) é enviada por stdin ao `gpg`/`pass insert`.
- **Backend Bitwarden**: para abrir a conta, o omapass lê o `data.json` do `bw` (só a conta ativa, a chave cifrada e os itens — nunca os tokens de acesso, e sem jamais escrever no arquivo) e decifra com a criptografia do Bitwarden: PBKDF2-SHA256 ou Argon2id conforme a conta, HKDF, AES-256-CBC com HMAC-SHA256 verificado antes de decifrar e RSA-OAEP para chaves de organização, via Botan. A senha mestra fica em memória só até o `bw unlock` em segundo plano terminar. A senha mestra vai para o `bw` por variável de ambiente (`--passwordenv`) e o JSON de itens e pastas (que carrega a senha) pelo stdin — nada disso aparece em argv. A chave de sessão fica num `Secret` e só chega ao `bw` pela variável `BW_SESSION` de cada processo filho. Enquanto o cofre está aberto, os itens (senhas incluídas) ficam na memória do omapass, para não pagar alguns segundos do `bw` a cada cópia; são descartados ao travar. Travar o cofre (auto-lock, `Ctrl+Q`, travar a tela) roda `bw lock`, o que **também encerra sessões do `bw` abertas no terminal**, e todo desbloqueio pelo omapass invalida chaves de sessão anteriores.
- **Desbloqueio por PIN**: nenhum backend aceita PIN (o `bw` e o `op` só conhecem a senha mestra, um `.kdbx` é cifrado com a dele, e o pass quer a passphrase GPG) — então é a **senha do banco** que fica guardada, cifrada com uma chave derivada do PIN (PBKDF2-SHA256, 600.000 iterações, com salt aleatório) no formato AES-256-CBC + HMAC-SHA256, no chaveiro do sistema (`secret-tool`, atributos `service=omapass account=pin:<caminho do banco>` — um por banco). O contador de tentativas erradas fica no `omapass.conf` sob um resumo SHA-256 do caminho, para o arquivo não listar onde estão seus bancos. O PIN em si não é guardado, nem um hash dele: o PIN errado falha na verificação do HMAC. **O limite honesto:** um PIN de 4 dígitos são 10.000 combinações, e quem conseguir ler o chaveiro pode testá-las offline — as 600.000 iterações são a única barreira, e o limite de 5 tentativas é da interface, não da criptografia. Use 6 dígitos ou mais — ou marque letras e símbolos, que é o jeito barato de multiplicar isso por milhares — e deixe o PIN desligado em máquina compartilhada. Nem a senha mestra nem o PIN passam por argumentos de processo.
- **Backend 1Password**: a senha mestra é digitada no próprio prompt do `op` (que roda com um terminal emprestado do `script`), a Secret Key vai pela variável de ambiente `OP_SECRET_KEY` e o JSON dos itens (que carrega a senha) pelo stdin do `op item create`/`op item edit` — nada disso aparece em argv, que o próprio `op` avisa ser legível por outros processos; o ambiente de um processo, ao contrário da linha de comando, só é legível pelo próprio usuário. O token de sessão fica num `Secret` e só chega ao `op` pela variável de ambiente que o próprio `op` nomeou ao devolvê-lo. A senha mestra **não** fica guardada depois de abrir: quando a sessão expira (30 minutos de inatividade), o omapass tranca e pede a senha de novo, em vez de manter a senha em memória para renovar sozinho. Enquanto o cofre está aberto, os itens já abertos (senhas incluídas) ficam na memória do omapass e são descartados ao travar. Travar o cofre roda `op signout`, o que **também encerra a sessão do `op` no terminal**.
- Senhas e passphrases circulam em um tipo `Secret`, que mantém uma cópia própria e sobrescreve a memória ao ser destruído. A exceção inevitável é o campo de senha do formulário de edição: um campo editável precisa do texto em claro enquanto está na tela.
- Ao copiar uma senha, o conteúdo é marcado como sensível para o `wl-clipboard` (mime `x-kde-passwordManagerHint`, que gerenciadores como o cliphist respeitam para não gravar no histórico) e o clipboard é limpo automaticamente após 10 segundos, com contagem regressiva visível na interface.
- **`~/.config/omapass/history`** guarda só HMACs (com chave aleatória local em `.history_key`, 0600) e timestamps de uso, nunca o conteúdo das entradas — mas ainda revela para outro usuário local com acesso ao arquivo quantas entradas existem e o padrão de uso.
- **Bloqueio manual**: `ESC` ou `q` com um banco aberto o travam na hora, pelo mesmo caminho do auto-lock abaixo — o `Vault` é descartado da memória e a interface volta para a lista de bancos. Na lista, as mesmas teclas fecham o omapass.
- **Auto-lock por inatividade**: por padrão, 10 minutos sem uso travam o banco desbloqueado — o `Vault` (senha/passphrase incluída) é descartado da memória e a interface volta pra tela de bancos, pedindo pra desbloquear de novo. Ajustável (ou desativável) via `lock_minutes` no `config.toml` (veja [Configuração](#configuração)).
- **Fecha ao travar a tela do sistema**: quando a sessão do desktop é bloqueada, o omapass fecha por completo (não só trava) — não fica um banco desbloqueado exposto atrás da tela de bloqueio. Reage tanto ao sinal `Lock` do logind (GNOME, KDE, qualquer setup com `loginctl lock-session`) quanto, especificamente no Hyprland/Omarchy — que não passa pelo logind pra travar a tela — sondando `omarchy-hyprland-session-locked` a cada 2s. Sem nenhum dos dois disponíveis, esse fechamento automático simplesmente não acontece (o auto-lock por inatividade acima continua funcionando normalmente).

## Configuração

`Ctrl+O` abre as configurações dentro do omapass, de qualquer tela. O modal edita o
`config.toml` e aplica na hora o diretório de busca, a ordenação por uso, o auto-lock e a lista
de palavras do gerador — as opções que valem sem reiniciar. Tema e idioma continuam só no
arquivo, porque são lidos uma vez na abertura.

Ao gravar, só os valores dessas chaves mudam: comentários, ordem das linhas e chaves que o
omapass não conhece ficam como estavam. `Ctrl+F` no modal abre o seletor de arquivos para uma
lista de palavras sua; o arquivo escolhido é **copiado** para `~/.config/omapass/wordlists/`, e o
caminho da cópia é gravado — assim a lista continua valendo se você mover ou apagar o original.
Listas com menos de 1.296 palavras (o mínimo do `keepassxc-cli`) são recusadas na hora, com o
número de palavras na mensagem.

Arquivos em `~/.config/omapass/`:

- `config.toml` — caminho de busca, recency, tema ativo, idioma, tempo de auto-lock e lista de palavras do gerador
- `themes/*.toml` — sobreposições de cores
- `wordlists/*` — listas de palavras trazidas pelo modal de configurações

> **Vindo do fpass:** se `~/.config/omapass` não existir e `~/.config/fpass`
> existir, o omapass continua usando o diretório antigo — histórico, temas e
> bancos criados pela interface seguem funcionando sem nenhum passo manual.
> Para adotar o nome novo, basta `mv ~/.config/fpass ~/.config/omapass`.

`path` define onde o omapass procura **tanto** arquivos `.kdbx` quanto password-stores do pass (diretórios com `.gpg-id`); o `~/.password-store` convencional é sempre verificado, mesmo que `path` aponte para outro lugar.

`language` controla o idioma da interface, em ordem de prioridade: (1) valor explícito no config.toml (`"pt-BR"`/`"en"`); (2) na ausência de um valor explícito (`"auto"` ou omitido), autodetecção pelo `$LANG`/`$LC_ALL` do sistema; (3) se nada foi configurado nem detectado, o padrão é inglês. Só o texto gerado pelo próprio omapass é traduzido — mensagens de erro que vêm direto do `keepassxc-cli`, `pass` ou `gpg` continuam no idioma dessas ferramentas, fora do controle do omapass.

Exemplo de `config.toml`:

```toml
[general]
path = "~/docs/keepass"
recency = true
theme = "default"
language = "pt-BR"
lock_minutes = 10

[generator]
wordlist = "auto"
```

`lock_minutes` define, em minutos, quanto tempo de inatividade até o banco desbloqueado ser travado (a interface volta pra tela de bancos, pedindo a senha de novo). Ausente, o padrão é 10; `lock_minutes = false` desativa o auto-lock por completo, voltando ao comportamento de sempre desbloqueado enquanto o omapass está aberto.

### Cores

Por padrão (`theme = "default"`) as cores vêm do tema ativo do Omarchy, em
`~/.local/state/omarchy/current/theme/colors.toml`, e são reaplicadas na hora
quando você troca de tema — não é preciso reiniciar o omapass. Sem Omarchy
instalado, o omapass usa Catppuccin Mocha ou Latte conforme a preferência
clara/escura do desktop.

Um tema próprio sobrepõe apenas os papéis que ele declarar; o resto continua
vindo do Omarchy. Em `~/.config/omapass/themes/tema.toml`:

```toml
[theme]
name = "meu-tema"

[colors]
Title = "#00AAAA"
Base = "#CCCCCC"
Guidance = "#666666"
```

e então `theme = "meu-tema"` no `config.toml`. Os papéis disponíveis são
`Title`, `Base`, `Guidance`, `Annotation`, `Important`, `AlertInfo`,
`AlertWarn` e `AlertError`.

### Fonte e tamanho do texto

O omapass não embute nenhuma fonte: a interface inteira usa a família genérica
`monospace`, que é exatamente o que o `omarchy font set` configura em
`~/.config/fontconfig/fonts.conf`. Trocar a fonte do sistema troca a do
omapass:

```bash
omarchy font list
omarchy font set "CaskaydiaMono Nerd Font"
```

Como o Qt resolve o fontconfig na inicialização, a mudança aparece ao reabrir o
omapass — o mesmo comportamento que o Omarchy avisa para o Ghostty e o Foot.

O tamanho do texto segue o do desktop, ao vivo — `omarchy display text size`,
ou o `text-scaling-factor` do GNOME.

## Atalhos

Lista completa disponível a qualquer momento com `Ctrl+?`. Os mais essenciais:

| Tecla | Ação |
|-------|------|
| `j` / `k` | Navegar para baixo/cima |
| `gg` / `G` | Ir para o topo/final |
| `Ctrl+U` / `Ctrl+D` | Meia página para cima/baixo |
| `Ctrl+N` / `Ctrl+P` | Próximo/anterior (funciona na busca e nas dropdowns) |
| `/`, `f` ou `i` | Entrar no modo de busca |
| `Enter` | Copiar senha / Confirmar |
| `Tab` | Ver detalhes da entrada |
| `Espaço` | Menu de ações |
| `Ctrl+A` / `Ctrl+E` / `Ctrl+X` | Adicionar / editar / excluir (na tela de bancos, `Ctrl+X` sai de uma conta Bitwarden ou 1Password) |
| `Ctrl+G` | Gerar senha (na lista, ou sobre o campo Senha do formulário) |
| `Ctrl+I` | Ativar/desativar o desbloqueio por PIN (do banco aberto) |
| `Ctrl+O` | Abrir as configurações |
| `ESC` / `q` | Cancelar; com um banco aberto, bloqueia e volta para a lista; na lista, sai do omapass |
| `Ctrl+Q` | Sair do programa |
| `Ctrl+C` | Sair do programa (fora de campos de texto, onde copia) |
