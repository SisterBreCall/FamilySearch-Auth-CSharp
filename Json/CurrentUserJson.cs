using System.Collections.Generic;

namespace CurrentUserResource
{
    public class Artifacts
    {
        public string href;
    }

    public class Links
    {
        public Person person;
        public Self self;
        public Artifacts artifacts;
    }

    public class Person
    {
        public string href;
    }

    public class CurrentUserJson
    {
        public List<User> users;
    }

    public class Self
    {
        public string href;
    }

    public class User
    {
        public string id;
        public string contactName;
        public string helperAccessPin;
        public string givenName;
        public string familyName;
        public string email;
        public string country;
        public string gender;
        public string birthDate;
        public string preferredLanguage;
        public string displayName;
        public string personId;
        public string treeUserId;
        public Links links;
    }
}