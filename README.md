# Zyntra Certificate Manager

Estático • Client-Side • Privacy First • by Zyntra

Analisa um PDF assinado (referência) e prepara um PDF sem assinatura (destino) para assinatura posterior. Tudo roda no navegador: sem backend, sem banco, sem upload.

## Executar

Não há build. Use um servidor estático local (o worker do PDF.js não funciona bem via `file://`):

```bash
cd zyntra-certificate-manager
python3 -m http.server 8080   # abra http://localhost:8080
```

## Publicar

Netlify ou Vercel: envie a pasta como site estático (sem comando de build, diretório de publicação `.`).

## Bibliotecas (CDN, versões fixas)

- PDF.js 3.11.174: visualização, contagem de páginas.
- pdf-lib 1.17.1: metadados, campos de formulário, inserção de campo de assinatura vazio.
- Inter (Google Fonts). Para uso 100% offline, baixe esses arquivos e ajuste as tags em `index.html`.

## O que a ferramenta faz

- Lê assinaturas pelo `/ByteRange` e `/Contents` e interpreta o PKCS#7: titular, emissor, CA raiz (quando incorporada), validade, algoritmos, data declarada.
- Confere o hash do trecho assinado (SHA-1/256/384/512) contra o `messageDigest` da assinatura.
- Mostra campos de assinatura vazios do destino, compara metadados e exporta o PDF.
- Exporta (1) cópia com bytes idênticos ou (2) cópia com um campo de assinatura vazio, somente se o destino não tiver assinaturas.

## O que NÃO faz

- Não valida a assinatura criptográfica, a cadeia de confiança, a revogação (CRL/OCSP) nem carimbo de tempo confiável. Um certificado incorporado ou um hash que confere não significam assinatura válida. Valide no Adobe Acrobat ou em validar.iti.gov.br.
- Não assina documentos, não pede senhas, não toca em chaves privadas e não modifica assinaturas existentes.
- PDFs protegidos por senha não são suportados.

## Privacidade

Arquivos ficam apenas na memória da aba. Nada é gravado em localStorage, cookies ou disco. O botão "Limpar arquivos da memória" descarta tudo.
