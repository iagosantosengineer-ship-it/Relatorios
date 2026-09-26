# Relatório de Detecção de Segurança — Execução Suspeita via PowerShell

**Analista:** Iago dos Santos
**Data do incidente:** 26/09/2026
**Ambiente:** Home Lab (Wazuh SIEM + Sysmon)
**Classificação:** Simulação de ataque (Red Team interno / Blue Team interno)
**Severidade do alerta:** Baixa (Nível 4 — Wazuh)

---

## 1. Resumo Executivo

Durante um exercício controlado de simulação de ataque em ambiente de laboratório, foi identificado — via **Wazuh SIEM** integrado a agentes **Sysmon** — um evento de criação de processo em que uma instância do **PowerShell** iniciou uma **segunda instância do PowerShell** com parâmetros associados a técnicas de execução discreta (`-nop -w hidden`). O comportamento é mapeado pela matriz **MITRE ATT&CK** na técnica **T1059.001 – Command and Scripting Interpreter: PowerShell**, tática de **Execution**.

O objetivo deste relatório é documentar o processo de detecção, análise e resposta, seguindo uma estrutura próxima à utilizada por analistas SOC Nível 1/2 em ambientes corporativos.

---

## 2. Ambiente de Detecção

| Item | Detalhe |
|---|---|
| Ferramenta de coleta | Sysmon (Microsoft Sysinternals) |
| SIEM | Wazuh 4.x |
| Host afetado | `DESKTOP-JSR3F4F` (agente `windows-pc`) |
| IP do agente | 192.168.56.103 |
| Usuário associado | `DESKTOP-JSR3F4F\Funcionario` |
| Regra Wazuh acionada | ID 92027 — "Powershell process spawned powershell instance" |
| Grupos da regra | sysmon, sysmon_eid1_detections, windows |

---

## 3. Detalhes do Alerta

- **Event ID (Sysmon):** 1 — Process Create
- **Data/Hora (UTC):** 2026-09-26 20:42:17
- **Processo pai:** `powershell.exe` (PID 1756)
- **Processo filho:** `powershell.exe` (PID 5212)
- **Linha de comando:**
  ```
  "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" -nop -w hidden -c Get-Process
  ```
- **Hash (SHA256):** `9785001B0DCF755EDDB8AF294A373C0B87B2498660F724E76C4D53F9C217C7A3`
- **Integridade do processo:** High
- **Diretório de execução:** `C:\Windows\system32\`

---

## 4. Análise Técnica

O ponto de atenção não é a execução do PowerShell em si — algo extremamente comum em ambientes Windows — mas sim **dois fatores combinados**:

1. **Processo pai também é PowerShell.** Um PowerShell chamando outro PowerShell é um padrão frequentemente associado a scripts de automação legítimos, mas também é uma técnica usada por atacantes para encadear execuções, ofuscar a origem de um comando ou escapar de restrições aplicadas ao processo pai original.
2. **Flags utilizadas na linha de comando:**
   - `-nop` (`-NoProfile`): impede o carregamento do perfil do usuário, reduzindo o log de eventos gerados e acelerando a execução — comum em scripts automatizados, mas também em execuções que buscam "passar despercebidas".
   - `-w hidden` (`-WindowStyle Hidden`): oculta a janela do console do usuário. Esse é o indicador mais relevante do alerta, pois execução oculta de processo é um comportamento típico de tentativa de evitar detecção visual por parte do usuário da máquina.

Nesse caso específico, o comando executado (`Get-Process`) é **benigno** — foi usado propositalmente no teste para simular o *padrão* de comportamento sem causar impacto real, já que o objetivo do exercício é validar a **capacidade de detecção**, não executar uma ação maliciosa de fato.

> **Observação para o relatório real de um SOC:** normalmente, o próximo passo da investigação seria correlacionar esse evento com Event ID 3 (Network Connection) e Event ID 11 (File Create) do mesmo `ProcessGuid`, para verificar se houve download de payload, conexão de rede suspeita ou criação de arquivos após a execução oculta.

---

## 5. Mapeamento MITRE ATT&CK

| Tática | Técnica | ID |
|---|---|---|
| Execution | Command and Scripting Interpreter: PowerShell | T1059.001 |

---

## 6. Indicadores de Comprometimento (IOCs)

| Tipo | Valor |
|---|---|
| Hash SHA256 (powershell.exe) | 9785001B0DCF755EDDB8AF294A373C0B87B2498660F724E76C4D53F9C217C7A3 |
| Padrão de linha de comando | `powershell.exe -nop -w hidden -c <comando>` |
| Host | DESKTOP-JSR3F4F |

> O hash acima corresponde ao binário legítimo do PowerShell da Microsoft — não é um indicador de malware por si só, e sim um dado de contexto registrado para fins de rastreabilidade do processo.

---

## 7. Resposta e Contenção

Como se tratou de um teste controlado em home lab, não houve ação de contenção real. Em um ambiente de produção, as ações recomendadas seriam:

- Isolar o host da rede (via EDR ou VLAN de quarentena) até confirmação de que a atividade é legítima.
- Coletar a árvore completa de processos (parent/child) via Sysmon para descartar execução de payload adicional.
- Verificar se o usuário `Funcionario` realmente executou o comando ou se há indício de sessão comprometida (RDP, WMI, PsExec).
- Escalar para Nível 2 caso sejam encontradas conexões de rede ou criação de arquivos suspeitos associados ao mesmo `ProcessGuid`.

---

## 8. Recomendações

1. **Habilitar PowerShell Script Block Logging e Module Logging** via GPO — o Event ID 1 do Sysmon mostra a linha de comando, mas não o conteúdo de scripts executados via `-EncodedCommand`, por exemplo.
2. **Considerar PowerShell Constrained Language Mode** em máquinas de usuários finais que não precisam de PowerShell administrativo.
3. **Ajustar a severidade da regra 92027** para subir de nível quando a flag `-w hidden` ou `-enc`/`-EncodedCommand` estiver presente na linha de comando, já que isso reduz falsos positivos de scripts legítimos de automação.
4. **Criar uma regra de correlação** que combine este evento com conexões de rede subsequentes do mesmo processo, elevando a severidade automaticamente se houver tráfego de saída incomum.

---

## 9. Lições Aprendidas

- Consegui validar o pipeline completo Sysmon → Wazuh Manager → Wazuh Dashboard, confirmando que o agente Windows está enviando e correlacionando eventos corretamente.
- Reforcei o entendimento de que `-w hidden` e `-nop` são flags-chave a monitorar mesmo quando o comando executado é inofensivo, pois o **padrão de comportamento** já é um indicador válido de possível uso malicioso do interpretador.

---

## Anexo — Log bruto (Wazuh, resumido)

```json
{
  "rule": {
    "id": "92027",
    "level": 4,
    "description": "Powershell process spawned powershell instance",
    "mitre": { "technique": ["PowerShell"], "id": ["T1059.001"], "tactic": ["Execution"] }
  },
  "data": {
    "win": {
      "eventdata": {
        "commandLine": "\"C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe\" -nop -w hidden -c Get-Process",
        "parentImage": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
        "user": "DESKTOP-JSR3F4F\\Funcionario"
      }
    }
  }
}
```

---
*Relatório produzido em ambiente de laboratório pessoal para fins de estudo e portfólio em cibersegurança (Blue Team / SOC).*
