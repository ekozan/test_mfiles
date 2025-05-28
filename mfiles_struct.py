from enum import Enum, auto
from typing import Optional, List, Any

class MFDataType(Enum):
    Text = auto()
    MultiLineText = auto()
    Integer = auto()
    Integer64 = auto()
    Floating = auto()
    Date = auto()
    Time = auto()
    FILETIME = auto()
    Lookup = auto()
    MultiSelectLookup = auto()
    Uninitialized = auto()
    ACL = auto()
    Boolean = auto()

class MFFolderContentItemType(Enum):
    ViewFolder = auto()
    PropertyFolder = auto()
    # Ajouter d'autres types au besoin

class Lookup:
    def __init__(self, item: int = 0):
        self.Item = item

class PropertyFolder:
    def __init__(
        self,
        DataType: MFDataType,
        Value: Any = None,
        DisplayValue: str = "",
        Lookup: Optional[Lookup] = None,
        Lookups: Optional[List[Lookup]] = None
    ):
        self.DataType = DataType
        self.Value = Value
        self.DisplayValue = DisplayValue
        self.Lookup = Lookup
        self.Lookups = Lookups or []

class View:
    def __init__(self, ID: int, Name: str):
        self.ID = ID
        self.Name = Name

class FolderContentItem:
    def __init__(
        self,
        FolderContentItemType: MFFolderContentItemType,
        View: Optional[View] = None,
        PropertyFolder: Optional[PropertyFolder] = None
    ):
        self.FolderContentItemType = FolderContentItemType
        self.View = View
        self.PropertyFolder = PropertyFolder

class FolderContentItems:
    def __init__(self, items: list):
        self.Items = []
        for item in items:
            item_type = MFFolderContentItemType[item['FolderContentItemType']]
            view = None
            prop_folder = None

            if 'View' in item and item['View'] is not None:
                view = View(ID=item['View']['ID'], Name=item['View']['Name'])
            if 'PropertyFolder' in item and item['PropertyFolder'] is not None:
                pf = item['PropertyFolder']
                data_type = MFDataType[pf['DataType']]
                lookup = Lookup(item=pf['Lookup']['Item']) if pf.get('Lookup') else None
                lookups = [Lookup(item=l['Item']) for l in pf.get('Lookups',[])]
                prop_folder = PropertyFolder(
                    DataType=data_type,
                    Value=pf.get('Value'),
                    DisplayValue=pf.get('DisplayValue', ""),
                    Lookup=lookup,
                    Lookups=lookups
                )
            self.Items.append(
                FolderContentItem(
                    FolderContentItemType=item_type,
                    View=view,
                    PropertyFolder=prop_folder
                )
            )
