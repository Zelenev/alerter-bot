from aiogram import Bot, Dispatcher, executor, types
from aiogram.contrib.fsm_storage.memory import MemoryStorage
from aiogram.dispatcher.filters.state import StatesGroup, State
from aiogram.dispatcher import FSMContext
import logging
import time
from elasticsearch import Elasticsearch
import asyncio
from urllib.request import urlopen
from ruamel.yaml import YAML
from dotenv import load_dotenv
import os


load_dotenv()
storage = MemoryStorage()
bot = Bot(os.getenv('TOKEN'))
dp = Dispatcher(bot, storage=storage)


#Состояния бота
class BotStates(StatesGroup):
    add = State()

# Запуск бота и старт отправки запросов
@dp.message_handler(commands=['start'])
async def cmd_start(message: types.message):
    await message.answer(f'Привет, {message.from_user.full_name}, начинаю отправлять запросы в Elasticsearch')

    logging.info(f'{message.from_user.id} {message.from_user.full_name} {time.asctime()}, Установлено состояние start')

    while True:
        try:
            logging.info(f'{time.asctime()}, запрос отправлен')
            j = 1
            ELASTIC_PASSWORD = os.getenv('ELASTIC')
            es = Elasticsearch(f"http://elastic:{ELASTIC_PASSWORD}@178.20.43.177:9200")

            # Хочу узнать количество документов, то есть правил в индексе
            count_of_doc = es.count(index="alert-rules")
            counter = count_of_doc['count']
            print("Правил в индексе: ", counter)

            while j <= counter:
                # Забираю данные из индекса alert-rules и кладу в переменную request
                data = es.get(index="alert-rules", id=j)
                request = data['_source']['content']
                rule_name = data['_source']['name']
                rule_index = data['_source']['index']

                # Запрос на поиск (это все можно сделать отдельной функцией), более универсально под каждый случай, каждое правило
                resp = es.search(index="logstash-*", body=request, size=50)['hits']['hits']

                if rule_index == 'logstash-winlogbeat':
                    if not resp:
                        print("Нет событий, удовлетворяющих правилу ", j)
                    else:
                        for hit in resp:
                            doc_id = hit["_id"]
                            index_name = hit["_index"]
                            doc_message = hit["_source"]["message"]
                            print(doc_id +" "+index_name)
                            await bot.send_message(message.chat.id, str(rule_name +
                                "\n\nСсылка на событие: https://cloud-marin.ru/app/discover#/doc/302c4f50-ba00-11ed-adee-d738b3d4b04a/" + index_name + "?id=" + doc_id)
                                                   +"\n"+str(doc_message))

                elif rule_index == 'logstash-openvpn':
                    if not resp:
                        print("Нет событий, удовлетворяющих правилу ", j)

                    else:
                        for hit in resp:
                            doc_id = hit["_id"]
                            index_name = hit["_index"]
                            client_name = hit["_source"]["source.user"]
                            client_ip = hit["_source"]["source.ip"]

                            await bot.send_message(message.chat.id, str(rule_name +
                                "\n\nСсылка на событие: https://cloud-marin.ru/app/discover#/doc/302c4f50-ba00-11ed-adee-d738b3d4b04a/" + index_name + "?id=" + doc_id)
                                                   +"\n\n"+"Пользователь: "+ str(client_name)+"\n"+"IP-адрес: "+str(client_ip))

                j += 1
        except:
            print("Произошла ошибка!!!")
        await asyncio.sleep(60)

#Установка состояния add
@dp.message_handler(commands=['add'])
async def cmd_add(message: types.message):
    await message.answer('Пришли мне файл с правилом (.yml)')
    await BotStates.add.set()
    logging.info(f'{message.from_user.id} {message.from_user.full_name} {time.asctime()}, Установлено состояние add rule')

async def reset_state(message: types.message, state: FSMContext):
    await state.finish()
    await message.answer(f'{message.from_user.full_name}, Состояние сброшено')

#Функция, которая слушает состояние add
@dp.message_handler(content_types=['document', 'text'], state=BotStates.add)
async def add_rule(message: types.message, state: FSMContext):

    print(message.text)
    if str(message.text) == "/reset":
        await state.finish()
        await message.answer(f'{message.from_user.full_name}, Состояние сброшено')
    else:
        try:
            file_id = message.document.file_id
            file_info = await bot.get_file(file_id)
            with urlopen('http://api.telegram.org/file/bot' + os.getenv('TOKEN') + '/' + file_info.file_path) as f:
                filedata = f.read().decode('utf-8')

            ELASTIC_PASSWORD = os.getenv('ELASTIC')
            es = Elasticsearch(f"http://elastic:{ELASTIC_PASSWORD}@178.20.43.177:9200")

            yaml = YAML(typ="safe")
            data = yaml.load(filedata)

            count = es.count(index="alert-rules")['count']
            res = es.index(index="alert-rules", id=count + 1, body=data)
            print(res['result'])
            await bot.send_message(message.chat.id, "Правило успешно добавлено!")
        except:
            await bot.send_message(message.chat.id, "Ошибка добавления!\nИсправьте ошибки и попробуйте снова")

    await state.finish()


@dp.message_handler()
async def query(message: types.message):
    await message.answer('Сейчас я просто отправляю запросы в Elasticsearch')

if __name__ == '__main__':
    executor.start_polling(dp, skip_updates=True)