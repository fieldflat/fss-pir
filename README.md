# Demo for 2-Party PIR

## 1. docker-compose up

下記コマンドを実行し、2つの Party を立てる。

```
$ docker-compose up -d
```

## 2. 鍵生成

下記コマンドを実行し、関数のシェアに相当する鍵をを生成する。

```
### localhost

$ go run main.go pir_genkey
```

コマンド実行後、keys ディレクトリに下記の鍵が生成されていることを確認する。

- fssKeys_party0 (Party0 用)
- fssKeys_party1 (Party1 用)
- NumBits (Party0,1 共用)
- PriKeys (Party0,1 共用)

```
### localhost

$ ls -l ./keys/
```

## 3. 各コンテナでプロトコルを実行

各コンテナにログインし、下記コマンドを実行し、先ほど生成した鍵を使用してプロトコルを実行する。

```
### container

$ go run main.go pir_eval
```

その後、results ディレクトリにプロトコルの実行結果が生成されていることを確認する。

```
### container

$ ls -l ./keys/
```

## 4. 復号

各コンテナの3の実行結果を収集し、検索結果を復号する。

```
### localhost

$ go run main.go pir_restore
```