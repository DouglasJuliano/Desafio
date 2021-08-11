# Desafio Cybersec

Foi criado o codigo na liguam Python onde no final da sua execução será gerado o arquivo `risk_report.csv` no diretório atual.

O codigo pode ser executado das seguintes formas:


### Python

- Verificar se a versão do Python é `3.9.X`
- Instalar as dependencia utilizando `pip install -r requirements.txt`
- Garantir que o arquivo de `log.txt`esteja no mesmo diretório
- Executar o comando `python main.py`
- Após a execução será gerado uma tabela de contadores na saida do codigo juntamente com o relatório que estará disponível na pasta `report`


### Docker

- Para executar em container rode o codigo `docker run --rm -v ${PWD}:/desafio/report --name desafio douglasjuliano/desafio`
- Após a execução será gerado uma tabela de contadores na saida do container juntamente com o relatório que estará disponível na pasta atual
