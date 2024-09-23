class MetadataDictionary(dict):
  """
  This is a very simple class that prints out a textproto using a dictionary.
  Realistically, we should not be re-inventing the wheel as we are doing here
  and we should be using protobuf instead.

  TODO(b/360322121): Use protobuf generated classes instead of this.
  """

  def __init__(self, field_name):
    super().__init__()
    self.field_name = field_name

  def _as_string(self, dict_items, width=2, depth=1):
    str = self.field_name + " {\n"
    for (key, value) in dict_items:
      if not isinstance(value, MetadataDictionary):
        str += (" " * width * depth) + f"{key}: {value}\n"
      else:
        str += (" " * width * depth) + value._as_string(value.items(), width,
                                                        depth + 1)
    str += (" " * width * (depth - 1)) + "}\n"
    return str

  def __repr__(self):
    return self._as_string(self.items())
