# Contribuindo com o Conexões

Obrigado pelo interesse! Correções, novas verificações de risco e melhorias de interface são bem-vindas.

Ao participar, você concorda em seguir o nosso [Código de Conduta](CODE_OF_CONDUCT.md).

## Antes de começar
- Para mudanças grandes, abra uma [issue](https://github.com/robsonpedroso/conexoes/issues) antes para combinarmos a abordagem.
- Bugs: descreva a versão do Windows, se o app estava como administrador, o que esperava e o que aconteceu.

## Ambiente
- Windows 10 ou 11
- [.NET SDK 10](https://dotnet.microsoft.com/download)
- Visual Studio, VS Code ou Rider

```powershell
dotnet build
dotnet test
dotnet run --project src\Conexoes.App   # pede elevação (UAC)
```

## Organização do código
| Pasta | Conteúdo |
|---|---|
| `src/Conexoes.Core` | Coletores (leem o sistema), regras de risco, verificação de assinatura, exportação. **Sem UI.** |
| `src/Conexoes.App` | Interface WPF (MVVM com CommunityToolkit.Mvvm) |
| `tests/Conexoes.Tests` | Testes xUnit |

## Diretrizes
- **Somente leitura:** coletores não alteram o sistema. Ações que modificam algo (ex.: finalizar processo) ficam na UI e pedem confirmação.
- **APIs, não texto de comandos:** use APIs do Windows (iphlpapi, WMI, COM etc.) em vez de interpretar a saída de `netstat`/`net user`, para funcionar em qualquer idioma.
- **Alertas são heurísticos:** toda regra nova em `RiskRules` precisa de um motivo claro, em português, dizendo o que conferir. Evite regras que gerem muitos falsos positivos em máquinas comuns.
- **Testes:** regras de risco e parsers devem ter teste em `tests/Conexoes.Tests`.
- Textos da interface em português do Brasil.

## Enviando um pull request
1. Faça um fork e crie um branch (`git checkout -b minha-melhoria`).
2. Garanta que `dotnet build` e `dotnet test` passam.
3. Abra o PR explicando o que mudou e por quê. Prints da interface ajudam.

> ⚠️ **Privacidade:** relatórios, CSVs e capturas de tela do app contêm dados reais da máquina
> (nome do computador, usuários, IPs, processos). Borre esses dados antes de anexar em issues ou PRs.

Ao contribuir, você concorda que sua contribuição será licenciada sob a [licença MIT](LICENSE) do projeto.
