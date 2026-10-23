# CoreCleaner

A skill for Claude Code and Codex that finds the disk space coding agents leave behind and clears only what you approve.

[English](#english) · [Português](#português) · [Español](#español)

```text
you    › my disk is full, use corecleaner
agent  › 38 items, about 1.6 GB you could clear. Open the page, tick what goes, paste the reply here.
you    › CoreCleaner plan 4f2a9c1e0b7d
         Trash: c1a2b3c c4d5e6f
agent  › Dry run: 2 items, 410 MB, nothing changed since the plan. Move them to the Trash?
```

---

## English

### What it is for

Coding agents leave things on your disk and never mention it: old sessions and logs, worktrees from tasks nobody finished, scratch clones with `node_modules` installed, package caches, downloaded models, headless browsers still running.

CoreCleaner finds those leftovers, tells you what each one is and what happens if it goes, and moves what you approve to the Trash. It archives a repo with unsaved work before moving it, and it deletes nothing for good.

Expect hundreds of MB to a few GB. On the author's Mac the agent leftovers came to about 2 GB on a 494 GB disk. Most of a full disk is your own files, your apps and what macOS keeps; CoreCleaner shows where that is instead of promising to clear it.

### Install

Needs Python 3.9 or newer and nothing from pip.

```sh
git clone https://github.com/Corewake-labs/CoreCleaner
cp -R CoreCleaner/skills/corecleaner ~/.claude/skills/corecleaner    # Claude Code
cp -R CoreCleaner/skills/corecleaner ~/.agents/skills/corecleaner    # Codex
```

Or in one line for both: `npx skills add corewake-labs/CoreCleaner -a claude-code -a codex -g`.

### How to use

1. Ask your agent: "my disk is full, use corecleaner".
2. The first time, it asks two things: whether to install [dua](https://github.com/Byron/dua-cli), a fast disk analyzer (one pinned build, checksum verified), and which language you want (English or Portuguese). It never asks again.
3. It reads the disk and lists candidates. Read-only, a few minutes.
4. It gives you a page, "Choose what to clean". Each kind of leftover has two lines in plain words, the safe ones come ticked, and a bar adds up what you picked. Press "Copy reply" and paste it in the chat. If you prefer, the agent asks in rounds of up to 4 questions instead.
5. The agent shows a dry run, asks once more, then moves the items to the Trash. Changed your mind? Ask for `undo`: it brings them back while the Trash is not emptied.
6. Empty the Trash yourself when you are sure. That is when the space comes back.

### What it never does

- Delete for good. Everything goes to the Trash; a cache cleaned by its own tool (`go clean -modcache`, for instance) is shown to you and run only after a second yes.
- Touch credentials, keys, agent settings, browser profiles or synced folders (iCloud, Dropbox, OneDrive, Google Drive).
- Act on a path you typed. It acts only on ids from a signed plan, and checks each item again right before moving it.
- Run as root, use `sudo` or empty your Trash.

### About Time Machine

On a Mac, Time Machine takes a local snapshot of the internal disk before each backup, even when backups go to an external drive. There is no switch to turn that off. macOS manages these snapshots: it keeps them for about a day and deletes them as soon as an app needs the space, and Finder already counts that space as available. After a day of heavy changes they can hold tens of GB (48 GB on the author's Mac).

If you want the space right now, run `tmutil deletelocalsnapshots /`. To keep them small, leave the backup drive connected so backups finish, or set Time Machine to back up manually.

---

## Português

### Para que serve

Agentes de código deixam coisas no seu disco e não avisam: sessões e logs antigos, worktrees de tarefas que ninguém terminou, clones de rascunho com `node_modules` instalado, caches de pacotes, modelos baixados, navegadores sem janela ainda rodando.

O CoreCleaner acha essas sobras, diz o que é cada uma e o que acontece se sair, e manda para a Lixeira só o que você aprovar. Ele arquiva o repositório com trabalho não salvo antes de mover, e não apaga nada de vez.

Espere de centenas de MB a poucos GB. No Mac do autor as sobras dos agentes deram cerca de 2 GB num disco de 494 GB. A maior parte de um disco cheio são seus arquivos, seus apps e o que o macOS guarda; o CoreCleaner mostra onde isso está em vez de prometer limpar.

### Instalação

Precisa de Python 3.9 ou mais novo, e nada do pip.

```sh
git clone https://github.com/Corewake-labs/CoreCleaner
cp -R CoreCleaner/skills/corecleaner ~/.claude/skills/corecleaner    # Claude Code
cp -R CoreCleaner/skills/corecleaner ~/.agents/skills/corecleaner    # Codex
```

Ou numa linha só para os dois: `npx skills add corewake-labs/CoreCleaner -a claude-code -a codex -g`.

### Como usar

1. Peça ao seu agente: "meu disco está cheio, usa o corecleaner".
2. Na primeira vez ele pergunta duas coisas: se pode instalar o [dua](https://github.com/Byron/dua-cli), um analisador de disco rápido (uma versão fixa, com checksum conferido), e em que idioma você quer (português ou inglês). Não pergunta de novo.
3. Ele lê o disco e lista os candidatos. Só leitura, alguns minutos.
4. Ele te entrega uma página, "Escolher o que limpar". Cada tipo de sobra tem duas linhas em linguagem simples, os seguros já vêm marcados e uma barra soma o que você escolheu. Clique em "Copiar resposta" e cole no chat. Se preferir, o agente pergunta em rodadas de até 4 perguntas.
5. O agente mostra uma simulação, pergunta mais uma vez e só então move os itens para a Lixeira. Mudou de ideia? Peça o `undo`: ele devolve tudo enquanto a Lixeira não for esvaziada.
6. Esvazie a Lixeira você mesmo quando tiver certeza. É aí que o espaço volta.

### O que ele nunca faz

- Apagar de vez. Tudo vai para a Lixeira; um cache limpo pela própria ferramenta (`go clean -modcache`, por exemplo) é mostrado a você e só roda depois de um segundo sim.
- Mexer em credenciais, chaves, configurações dos agentes, perfis de navegador ou pastas sincronizadas (iCloud, Dropbox, OneDrive, Google Drive).
- Agir sobre um caminho digitado. Ele só age sobre ids de um plano assinado, e confere cada item de novo logo antes de mover.
- Rodar como root, usar `sudo` ou esvaziar sua Lixeira.

### Sobre o Time Machine

No Mac, o Time Machine tira uma foto local do disco interno antes de cada backup, mesmo quando o backup vai para um HD externo. Não existe opção para desligar isso. O macOS cuida dessas fotos sozinho: guarda por cerca de um dia e apaga assim que algum app precisa do espaço, e o Finder já conta esse espaço como disponível. Depois de um dia de muitas mudanças elas podem segurar dezenas de GB (48 GB no Mac do autor).

Se quiser o espaço na hora, rode `tmutil deletelocalsnapshots /`. Para elas ficarem pequenas, deixe o HD do backup conectado para os backups terminarem, ou mude o Time Machine para backup manual.

---

## Español

### Para qué sirve

Los agentes de código dejan cosas en tu disco y no avisan: sesiones y logs viejos, worktrees de tareas que nadie terminó, clones de borrador con `node_modules` instalado, cachés de paquetes, modelos descargados, navegadores sin ventana que siguen corriendo.

CoreCleaner encuentra esos restos, te dice qué es cada uno y qué pasa si lo quitas, y manda a la Papelera solo lo que apruebes. Archiva el repositorio con trabajo sin guardar antes de moverlo, y no borra nada para siempre.

Espera de cientos de MB a pocos GB. En el Mac del autor los restos de los agentes sumaron unos 2 GB en un disco de 494 GB. Casi todo lo que llena un disco son tus archivos, tus apps y lo que guarda macOS; CoreCleaner te muestra dónde está eso en vez de prometer limpiarlo.

### Instalación

Necesita Python 3.9 o más nuevo, y nada de pip.

```sh
git clone https://github.com/Corewake-labs/CoreCleaner
cp -R CoreCleaner/skills/corecleaner ~/.claude/skills/corecleaner    # Claude Code
cp -R CoreCleaner/skills/corecleaner ~/.agents/skills/corecleaner    # Codex
```

O en una sola línea para los dos: `npx skills add corewake-labs/CoreCleaner -a claude-code -a codex -g`.

### Cómo se usa

1. Pídele a tu agente: "mi disco está lleno, usa corecleaner".
2. La primera vez pregunta dos cosas: si puede instalar [dua](https://github.com/Byron/dua-cli), un analizador de disco rápido (una versión fija, con checksum verificado), y en qué idioma lo quieres (por ahora, inglés o portugués). No vuelve a preguntar.
3. Lee el disco y lista los candidatos. Solo lectura, unos minutos.
4. Te da una página, "Choose what to clean" (en inglés o portugués). Cada tipo de resto tiene dos líneas en palabras sencillas, los seguros ya vienen marcados y una barra suma lo que elegiste. Pulsa "Copy reply" y pégala en el chat. Si prefieres, el agente pregunta en rondas de hasta 4 preguntas.
5. El agente muestra una simulación, pregunta una vez más y solo entonces mueve los elementos a la Papelera. ¿Cambiaste de idea? Pide `undo`: lo devuelve todo mientras no vacíes la Papelera.
6. Vacía la Papelera tú mismo cuando estés seguro. Ahí es cuando vuelve el espacio.

### Lo que nunca hace

- Borrar para siempre. Todo va a la Papelera; una caché que limpia su propia herramienta (`go clean -modcache`, por ejemplo) se te muestra y solo se ejecuta tras un segundo sí.
- Tocar credenciales, claves, configuraciones de los agentes, perfiles de navegador o carpetas sincronizadas (iCloud, Dropbox, OneDrive, Google Drive).
- Actuar sobre una ruta escrita a mano. Solo actúa sobre ids de un plan firmado, y revisa cada elemento otra vez justo antes de moverlo.
- Ejecutarse como root, usar `sudo` o vaciar tu Papelera.

### Sobre Time Machine

En un Mac, Time Machine toma una instantánea local del disco interno antes de cada copia, incluso cuando la copia va a un disco externo. No hay opción para apagarlo. macOS gestiona esas instantáneas solo: las guarda más o menos un día y las borra en cuanto una app necesita el espacio, y el Finder ya cuenta ese espacio como disponible. Tras un día de muchos cambios pueden ocupar decenas de GB (48 GB en el Mac del autor).

Si quieres el espacio ya, ejecuta `tmutil deletelocalsnapshots /`. Para que se queden pequeñas, deja conectado el disco de la copia para que las copias terminen, o pon Time Machine en copia manual.

---

## Reference

How every command works, what it refuses and its limits: [docs/REFERENCE.md](docs/REFERENCE.md). The contract of each subcommand: [docs/SPEC.md](docs/SPEC.md).

Windows support is beta and untested on a real machine. Linux is lightly tested; development happened on macOS.

```sh
python3 -m unittest discover -s tests -t .
```

## Credits and license

MIT, see [LICENSE](LICENSE). Ideas from luchasarie/agent-cleanup and daymade/claude-code-skills (no code copied), and dua-cli as an optional download: see [NOTICE](NOTICE).
