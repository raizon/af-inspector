from flask_wtf import FlaskForm
from wtforms import StringField, SelectField, BooleanField, SubmitField
from wtforms.validators import DataRequired, Length


class set_data_form(FlaskForm):
    incoming = StringField("PT AF Log Inspector")
    submit = SubmitField("Отправить")