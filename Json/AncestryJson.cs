using Newtonsoft.Json;
using System.Collections.Generic;

namespace AncestryResource
{
    public class Ancestry
    {
        public string href;
    }

    public class Collection
    {
        public string href;
    }

    public class Descendancy
    {
        public string href;
    }

    public class Display
    {
        public string name;
        public string gender;
        public string lifespan;
        public string ascendancyNumber;
        public string descendancyNumber;
    }

    public class Gender
    {
        public string type;
    }

    public class Identifiers
    {
        [JsonProperty("http://gedcomx.org/Persistent")]
        public List<string> httpgedcomxorgPersistent;
    }

    public class Links
    {
        public Collection collection;
        public Ancestry ancestry;
        public Person person;
        public Self self;
        public Descendancy descendancy;
    }

    public class Name
    {
        public bool preferred;
        public List<NameForm> nameForms;
    }

    public class NameForm
    {
        public string fullText;
        public List<Part> parts;
        public List<NameFormInfo> nameFormInfo;
        public string lang;
    }

    public class NameFormInfo
    {
        public string order;
    }

    public class Part
    {
        public string type;
        public string value;
    }

    public class Person
    {
        public string id;
        public bool living;
        public Gender gender;
        public Links links;
        public Identifiers identifiers;
        public List<Name> names;
        public Display display;
        public List<PersonInfo> personInfo;
    }

    public class Person2
    {
        public string href;
    }

    public class PersonInfo
    {
        public bool canUserEdit;
        public bool visibleToAll;
    }

    public class AncestryJson
    {
        public Links links;
        public List<Person> persons;
    }

    public class Self
    {
        public string href;
    }
}