# SEE-U-L4TER-Uma-C-psula-do-Tempo-Criptogr-fica


# Uso de api_test

**Cifrar**
```bash
echo "Hello World" > test.txt
./api_test.sh -r cifrar -f test.txt -e user2@example.com
```
Resultado (exemplo)
```json
{
  "data_hora": "202505200028",
  "file_path": "uploads/202505200028_test.txt.enc",
  "hmac": "977625b210661f824ce05e5411af4e0e832d25d0e20b0923604bd0460e9811b9"
}
```

**Decifrar**

json_tests/decifrar.json (exemplo, substituir dados para testar)
```json
{
  "email": "user2@example.com",
  "data_hora": "202505200028",
  "file_path": "uploads/202505200028_test.txt.enc",
  "hmac": "977625b210661f824ce05e5411af4e0e832d25d0e20b0923604bd0460e9811b9"
}
```

```bash
./api_test.sh -r decifrar -j json_tests/decifrar.json
```

Resultado (exemplo)
```json
{
  "mensagem_decifrada": "Hello World!\n"
}
```