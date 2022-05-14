import json
import random

if __name__ == '__main__':
    data = []
    for i in range(0, 1000):
        data.append({
            "id": i,
            "annual_income": random.randint(-10000, 100000)
        })
    with open('./jsondata/data1.json', mode='wt', encoding='utf-8') as file:
        json.dump(data, file, ensure_ascii=False, indent=4)