import json
import xmltodict
from attributedict.collections import AttributeDict


class CVRFDocument(AttributeDict):
    """
    (Schema Version)
    Document Title
    Document Type
    Document Publisher *
    Document Tracking *
    Document Notes *
    Document Distribution
    Aggregate Severity *
    Document References *
    Acknowledgements *

    Vulnerability **
    ProductTree **
    """

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.ProductTree = ProductTree(self.pop('ProductTree'))
        print(type(self.ProductTree))
        print(type(self.ProductTree.__dict__))
        print(self.ProductTree)

    def __str__(self):
        return "{} {}: {}".format(self.DocumentType, self.DocumentTracking.Identification.ID, self.DocumentTitle)

    # def products(self):
    #     if self.ProductTree is not None:
    #         pass
    #     else:
    #         return None # Product object from self node?
    #     return self.ProductTree.Branch

    @classmethod
    def from_xml(cls, xml, lazy=True):
        """
        Create a CVRFDocument from an existing XML file.
        :param xml: A file object from which to read the XML representation.
        :param lazy: If True (default) will delay parsing the document until elements are accessed.
        :return: A new CVRFDocument based on the given file.
        """
        # TODO: Might need streaming option for huge files
        # new_doc = cls()
        # new_doc.root = xmltodict.parse(xml)
        with open(xml, 'rb') as f:
            # new_doc.root = AttrDict(xmltodict.parse(f, dict_constructor=dict, encoding='utf-8'))
            new_doc = cls(xmltodict.parse(f, dict_constructor=dict, encoding='utf-8')['cvrfdoc'])

        if not lazy:
            # Expand full tree
            # TODO: Not needed if using xmltodict without streaming?
            pass

        return new_doc

        # def is_valid(self) -> bool:
        #     """
        #     Checks whether a CVRFDocument generates a valid CVRF XML document.
        #     :return: True, if the resulting document conforms to the specified schema. Otherwise False.
        #     """
        #     pass


class ProductTree():  # AttributeDict
    """
    Branch * (recursive)
    Full Product Name *
    Relationship *
    Product Groups *
    """

    def __init__(self, source_dict: dict):
        self.tree = AttributeDict(source_dict)

    def branches(self):
        if hasattr(self.tree, 'Branch') and self.tree.Branch is not None:
            return json.dumps(self.tree.Branch, indent=4)
        else:
            return ''

    def products(self):
        # print(self.branches())
        if hasattr(self.tree, 'Branch') and self.tree.Branch is not None:
            branch_products = []
            for b in self.tree.Branch.Branch:
                # print("Branch: ", b)
                branch_products.extend(ProductTree(b).products())
            return branch_products

        else:
            return [Product(self.tree.FullProductName['@ProductID'],
                            self.tree.FullProductName['#text'],
                            self.tree.FullProductName.get('CPE', None))]


class Product:
    def __init__(self, id, name, cpe=None):
        self.ProductID = id
        self.FullProductName = name
        self.CPE = cpe

    def __str__(self):
        return "({}) {}".format(self.ProductID, self.FullProductName)


class Vulnerability:
    """
    Ordinal
    Title
    ID *
    Notes *
    Discovery Date
    Release Date
    Involvements *
    CVE
    CWE *
    Product Statuses *
    Threats *
    CVSS Score Sets *
    Remediations *
    References *
    Acknowledgements *
    """
    pass
