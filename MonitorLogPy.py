import random
import datetime

# ================= MENU =================
def menu():
    nome_arq = 'log.txt'
    while True:
        print('\nMENU')
        print('1 - Gerar logs')
        print('2 - Analisar logs')
        print('3 - Gerar e Analisar logs')
        print('4 - SAIR')
        try:
            opc = int(input('Escolha uma opção: '))
        except:
            print('Entrada inválida')
            continue

        if opc == 1:
            qtd = int(input('Quantidade de logs: '))
            gerarArquivo(nome_arq, qtd)

        elif opc == 2:
            analisarLogs(nome_arq)

        elif opc == 3:
            qtd = int(input('Quantidade de logs: '))
            gerarArquivo(nome_arq, qtd)
            analisarLogs(nome_arq)

        elif opc == 4:
            print('Até mais.')
            break

        else:
            print('Opção inválida')


# ================= GERAÇÃO =================
def gerarArquivo(nome_arq, qtd):
    with open(nome_arq, 'w', encoding='utf-8') as arq:
        for i in range(qtd):
            arq.write(montarLog(i) + '\n')
    print('Log gerado')


def montarLog(i):
    data = gerarData(i)
    ip = gerarIp(i)
    recurso = gerarRecurso(i)
    metodo = gerarMetodo(i)
    status = gerarStatus(i)
    tempo = gerarTempo(i)
    agente = gerarAgente(i)
    protocolo = gerarProtocolo(i)
    tamanho = gerarTamanho(i)

    return f'[{data}] {ip} - {metodo} - {status} - {recurso} - {tempo}ms - {tamanho}B - {protocolo} - {agente} - /home'


def gerarData(i):
    base = datetime.datetime.now()
    delta = datetime.timedelta(seconds=i * random.randint(5, 20))
    return (base + delta).strftime('%d/%m/%Y %H:%M:%S')


def gerarIp(i):
    if 20 <= i <= 50:
        return '203.120.45.7'
    return f'{random.randint(10,200)}.{random.randint(10,200)}.{random.randint(0,250)}.{random.randint(1,200)}'


def gerarMetodo(i):
    if i % 3 == 0:
        return 'POST'
    return 'GET'


def gerarStatus(i):
    if i % 10 == 0:
        return 500
    if i % 7 == 0:
        return 404
    if i % 5 == 0:
        return 403
    return 200


def gerarRecurso(i):
    if i % 8 == 0:
        return '/admin'
    if i % 6 == 0:
        return '/login'
    return '/home'


def gerarTempo(i):
    return random.randint(50, 1000)


def gerarAgente(i):
    if i % 9 == 0:
        return 'Bot'
    return 'Chrome'


def gerarProtocolo(i):
    return 'HTTP/1.1'


def gerarTamanho(i):
    return random.randint(200, 2000)


# ================= EXTRAÇÃO MANUAL =================
def extrairCampos(linha):
    campos = ""
    atual = ""
    cont = 0

    for c in linha:
        if c == '-' and cont < 8:
            campos += atual.strip() + '|'
            atual = ""
            cont += 1
        else:
            atual += c

    campos += atual.strip()
    return campos


def pegarCampo(campos, pos):
    atual = ""
    indice = 0

    for c in campos:
        if c == '|':
            if indice == pos:
                return atual.strip()
            atual = ""
            indice += 1
        else:
            atual += c

    if indice == pos:
        return atual.strip()

    return ""


def extrairNumero(txt):
    num = ""
    for c in txt:
        if c >= '0' and c <= '9':
            num += c
    return int(num)


# ================= ANÁLISE =================
def analisarLogs(nome_arq):
    try:
        arq = open(nome_arq, 'r', encoding='utf-8')
    except:
        print('Arquivo não encontrado')
        return

    total = sucesso = erros = erros500 = 0
    somaTempo = 0
    maiorTempo = 0
    menorTempo = 999999

    rapidos = normais = lentos = 0
    status200 = status403 = status404 = status500 = 0

    recursoMais = ""
    recursoQtd = 0

    ipMais = ""
    ipQtd = 0

    ipErro = ""
    ipErroQtd = 0

    ultimoIP = ""
    contIP = 0

    bot = 0
    ultimoBot = ""

    tempoAnt = 0
    crescente = 0
    degradacao = 0

    erroSeq = 0
    falhaCritica = 0

    adminErro = 0

    sensivel = 0
    sensivelErro = 0

    for linha in arq:
        total += 1

        campos = extrairCampos(linha)

        ip = pegarCampo(campos, 0)
        metodo = pegarCampo(campos, 1)
        status = int(pegarCampo(campos, 2))
        recurso = pegarCampo(campos, 3)
        tempo = extrairNumero(pegarCampo(campos, 4))
        agente = pegarCampo(campos, 7)

        # sucesso / erro
        if status == 200:
            sucesso += 1
        else:
            erros += 1

        if status == 500:
            erros500 += 1

        # tempo
        somaTempo += tempo
        if tempo > maiorTempo:
            maiorTempo = tempo
        if tempo < menorTempo:
            menorTempo = tempo

        # classificação
        if tempo < 200:
            rapidos += 1
        elif tempo < 800:
            normais += 1
        else:
            lentos += 1

        # status
        if status == 200:
            status200 += 1
        elif status == 403:
            status403 += 1
        elif status == 404:
            status404 += 1
        elif status == 500:
            status500 += 1

        # IP mais ativo
        if ip == ultimoIP:
            contIP += 1
        else:
            if contIP > ipQtd:
                ipQtd = contIP
                ipMais = ultimoIP
            ultimoIP = ip
            contIP = 1

        # BOT (5 seguidos)
        if contIP >= 5:
            bot += 1
            ultimoBot = ip
            contIP = 0

        # recurso mais acessado
        if recurso == recursoMais:
            recursoQtd += 1
        else:
            if recursoQtd < 1:
                recursoMais = recurso
                recursoQtd = 1

        # erros por IP
        if status != 200:
            if ip == ipErro:
                ipErroQtd += 1
            else:
                if ipErroQtd < 1:
                    ipErro = ip
                    ipErroQtd = 1

        # admin indevido
        if recurso == '/admin' and status != 200:
            adminErro += 1

        # rotas sensíveis
        if recurso == '/admin' or recurso == '/config' or recurso == '/backup' or recurso == '/private':
            sensivel += 1
            if status != 200:
                sensivelErro += 1

        # degradação
        if tempo > tempoAnt:
            crescente += 1
            if crescente >= 3:
                degradacao += 1
                crescente = 0
        else:
            crescente = 0
        tempoAnt = tempo

        # falha crítica
        if status == 500:
            erroSeq += 1
            if erroSeq >= 3:
                falhaCritica += 1
                erroSeq = 0
        else:
            erroSeq = 0

    arq.close()

    disponibilidade = (sucesso / total) * 100
    taxaErro = (erros / total) * 100
    mediaTempo = somaTempo / total

    estado = "SAUDÁVEL"
    if falhaCritica > 0 or disponibilidade < 70:
        estado = "CRÍTICO"
    elif disponibilidade < 85:
        estado = "INSTÁVEL"
    elif disponibilidade < 95:
        estado = "ATENÇÃO"

    print('\n===== RELATÓRIO FINAL =====')
    print('Total de acessos:', total)
    print('Sucessos:', sucesso)
    print('Erros:', erros)
    print('Erros críticos:', erros500)
    print('Disponibilidade:', round(disponibilidade, 2), '%')
    print('Taxa erro:', round(taxaErro, 2), '%')
    print('Tempo médio:', round(mediaTempo, 2))
    print('Maior tempo:', maiorTempo)
    print('Menor tempo:', menorTempo)
    print('Rápidos:', rapidos)
    print('Normais:', normais)
    print('Lentos:', lentos)
    print('Status 200:', status200)
    print('Status 403:', status403)
    print('Status 404:', status404)
    print('Status 500:', status500)
    print('Recurso mais acessado:', recursoMais)
    print('IP mais ativo:', ipMais)
    print('IP com mais erros:', ipErro)
    print('Acessos indevidos admin:', adminErro)
    print('Degradação:', degradacao)
    print('Falhas críticas:', falhaCritica)
    print('Bots detectados:', bot)
    print('Último bot:', ultimoBot)
    print('Rotas sensíveis:', sensivel)
    print('Falhas rotas sensíveis:', sensivelErro)
    print('Estado final:', estado)
menu()
