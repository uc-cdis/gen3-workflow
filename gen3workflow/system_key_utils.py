from cryptography.fernet import Fernet
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine
from sqlalchemy.future import select

from gen3workflow import aws_utils
from gen3workflow.config import config
from gen3workflow.models import SystemKey


def encrypt(string):
    encryption_key = Fernet(config["ENCRYPTION_KEY"])
    return encryption_key.encrypt(bytes(string, encoding="utf8")).decode("utf8")


def decrypt(string):
    encryption_key = Fernet(config["ENCRYPTION_KEY"])
    return encryption_key.decrypt(bytes(string, encoding="utf8")).decode("utf8")


async def get_system_key(user_id):

    # get existing system keys for this user
    engine = create_async_engine(config["DB_CONNECTION_STRING"], echo=True)
    session_maker = async_sessionmaker(engine, expire_on_commit=False)
    async with session_maker() as session:
        async with session.begin():
            query = select(SystemKey).where(SystemKey.user_id == user_id)
            result = await session.execute(query)
    system_keys = result.scalars().all()

    # if there are existing keys, return the newest one
    newest_key = None
    for system_key in system_keys:
        if newest_key is None or system_key.created_time > newest_key.created_time:
            newest_key = system_key
    if newest_key:
        return newest_key.key_id, decrypt(newest_key.key_secret)

    # if there are no existing keys, create one
    key_id, key_secret = aws_utils.create_iam_user_and_key(
        user_id=user_id, system_key=True
    )
    system_key = SystemKey(
        key_id=key_id,
        key_secret=encrypt(key_secret),
        user_id=user_id,
    )
    async with session_maker() as session:
        async with session.begin():
            session.add(system_key)
    return key_id, key_secret
