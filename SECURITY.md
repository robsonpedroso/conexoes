# Política de segurança

## Versões suportadas
Correções de segurança são feitas apenas na versão mais recente publicada em
[Releases](https://github.com/robsonpedroso/conexoes/releases/latest).

## Como reportar uma vulnerabilidade
**Não abra uma issue pública.** Use o reporte privado do GitHub:

1. Acesse a aba [Security](https://github.com/robsonpedroso/conexoes/security) do repositório.
2. Clique em **Report a vulnerability**.
3. Descreva o problema, como reproduzir, a versão do app e do Windows e o impacto esperado.

Você receberá uma resposta assim que possível. Depois da correção publicada, o problema pode ser divulgado
com crédito a quem reportou, se desejar.

## Escopo
O Conexões roda **como administrador** e lê informações sensíveis da máquina. São exemplos de vulnerabilidade:
- execução de código ou elevação de privilégio através do app (ex.: entradas maliciosas no registro, tarefas ou nomes de processo);
- injeção de conteúdo no relatório HTML exportado;
- o app alterar o sistema sem ação explícita do usuário.

Comportamentos esperados, que **não** são vulnerabilidades:
- "Finalizar processo" encerra processos (pede confirmação);
- "Abrir local da inicialização" grava a última chave aberta do Regedit (`HKCU\...\Applets\Regedit\LastKey`) para abri-lo na chave certa.

Falsos positivos ou falsos negativos dos alertas também não são vulnerabilidades: os alertas são heurísticos.
Reporte-os numa [issue](https://github.com/robsonpedroso/conexoes/issues) normal.
