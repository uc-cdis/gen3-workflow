import pytest
from sqlalchemy import exc
from sqlalchemy.future import select

from gen3workflow.models import SystemKey
from tests.migrations.migration_utils import MigrationRunner


@pytest.mark.asyncio
async def test_e1886270d9d2_upgrade(reset_database, session):
    # state before the migration
    migration_runner = MigrationRunner()
    await migration_runner.downgrade("base")

    # the system_key table should not exist
    query = select(SystemKey)
    with pytest.raises(
        exc.ProgrammingError, match='relation "system_key" does not exist'
    ):
        result = await session.execute(query)
    await session.rollback()

    # run the migration
    await migration_runner.upgrade("e1886270d9d2")

    # the system_key table should now exist
    query = select(SystemKey)
    result = await session.execute(query)
    assert list(result.scalars().all()) == []
