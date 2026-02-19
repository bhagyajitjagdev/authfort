"""Alembic helper for developers sharing a database with AuthFort."""


def alembic_exclude():
    """Return an ``include_object`` filter that skips AuthFort tables.

    Use this in your own Alembic ``env.py`` so that ``autogenerate`` does not
    propose dropping ``authfort_*`` tables::

        from authfort import alembic_exclude

        context.configure(
            ...,
            include_object=alembic_exclude(),
        )
    """

    def include_object(object, name, type_, reflected, compare_to):
        if type_ == "table" and name.startswith("authfort_"):
            return False
        return True

    return include_object
