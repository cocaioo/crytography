#!/usr/bin/env python3
"""
Gerador/validador de paridade RSA para uso com CiberChief.

Gera chaves RSA (2048), cria assinaturas para `mensagem.txt` com
SHA-256/384/512 em HEX e BASE64, verifica localmente e exporta os
artefatos para `parity_artifacts/` para serem usados no CiberChief.

Uso:
    python test_rsa_parity.py

Saídas:
 - parity_artifacts/
   - local_private.pem
   - local_public.pem
   - signature-<sha>-<fmt>.sig
 - Relatório no stdout com resultados de verificação local

Observação: carrega dinamicamente `trabalhoSeg.py` do mesmo diretório.
"""
import os
import importlib.util
import sys


def load_crypto_class(script_path):
    spec = importlib.util.spec_from_file_location('trabalhoSeg', script_path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return getattr(module, 'CryptoTool')


def ensure_dir(path):
    if not os.path.exists(path):
        os.makedirs(path)


def main():
    base_dir = os.path.dirname(os.path.abspath(__file__))
    script_path = os.path.join(base_dir, 'trabalhoSeg.py')
    message_path = os.path.join(base_dir, 'mensagem.txt')

    if not os.path.isfile(script_path):
        print(f"Arquivo {script_path} não encontrado. Execute este script na pasta correta.")
        return
    if not os.path.isfile(message_path):
        print(f"Arquivo de mensagem {message_path} não encontrado. Crie um `mensagem.txt` no mesmo diretório.")
        return

    CryptoTool = load_crypto_class(script_path)
    crypto = CryptoTool()

    artifacts_dir = os.path.join(base_dir, 'parity_artifacts')
    ensure_dir(artifacts_dir)

    # 1) gerar par de chaves
    priv = os.path.join(artifacts_dir, 'local_private.pem')
    pub = os.path.join(artifacts_dir, 'local_public.pem')
    print('Gerando par de chaves RSA 2048...')
    res = crypto.generate_rsa_keys(2048, priv, pub)
    if not res.get('ok'):
        print('Erro ao gerar chaves:', res)
        return
    print('Chaves geradas em:', priv, pub)

    results = []
    for sha in (256, 384, 512):
        for fmt in ('BASE64', 'HEX'):
            sig_name = f'signature-{sha}-{fmt.lower()}.sig'
            sig_path = os.path.join(artifacts_dir, sig_name)

            print(f'Assinando mensagem com SHA-{sha}, formato {fmt} -> {sig_name} ...')
            sign_res = crypto.rsa_sign(priv, message_path, sig_path, sha, fmt)
            ok_sign = sign_res.get('ok', False)

            verify_res = { 'ok': False, 'msg': 'não executado' }
            if ok_sign:
                verify_res = crypto.rsa_verify(pub, message_path, sig_path, sha, fmt)

            results.append({
                'sha': sha,
                'format': fmt,
                'sig_file': sig_path,
                'sign_ok': ok_sign,
                'verify_ok': verify_res.get('ok', False),
                'verify_msg': verify_res.get('msg')
            })

    # resumo
    print('\nResumo das assinaturas e verificações locais:')
    for r in results:
        print(f"SHA-{r['sha']} {r['format']}: sign_ok={r['sign_ok']} verify_ok={r['verify_ok']} msg={r['verify_msg']}")

    print('\nArquivos exportados para:', artifacts_dir)
    print('Use os arquivos em parity_artifacts/ (public + signature files) para verificar no CiberChief.')


if __name__ == '__main__':
    main()
